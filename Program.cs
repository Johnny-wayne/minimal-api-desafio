using MinimalApi.Infraestrutura.Db;
using MinimalApi.DTOs;
using Microsoft.EntityFrameworkCore;
using minimalApi.Dominio.Interfaces;
using MinimalApi.Dominio.Servicos;
using MinimalApi.Dominio.ModelViews;
using Microsoft.AspNetCore.Mvc;
using minimalApi.Dominio.Entidades;
using MinimalApi.Dominio.Enuns;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.OpenApi.Models;
using Microsoft.Extensions.Options;
using Microsoft.AspNetCore.Authorization;

#region Builder
var builder = WebApplication.CreateBuilder(args);

var key = builder.Configuration.GetSection("Jwt").ToString();
if(string.IsNullOrEmpty(key)) key = "123456";

//Entities
builder.Services.AddScoped<IAdministradorServico, AdministradorServico>();
builder.Services.AddScoped<IVeiculoServico, VeiculoServico>();

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(options => {
    options.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme{
        Name = "Autorization",
        Type = SecuritySchemeType.Http,
        Scheme = "bearer",
        BearerFormat = "JWT",
        In = ParameterLocation.Header,
        Description = "Insira o token JWT aqui"
    });
    options.AddSecurityRequirement(new OpenApiSecurityRequirement{
        {
            new OpenApiSecurityScheme{
                Reference = new OpenApiReference{
                    Type = ReferenceType.SecurityScheme,
                    Id = "Bearer"
                }
            },
            new string[] {}
        }
    });
});


//Jwt token
builder.Services.AddAuthentication(option => {
    option.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    option.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
}).AddJwtBearer(option => {
    option.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateLifetime = true,
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(key)),
        ValidateIssuer = false,
        ValidateAudience = false
    };
});

builder.Services.AddAuthorization();

//context
builder.Services.AddDbContext<DbContexto>(options => {
    options.UseMySql(
        builder.Configuration.GetConnectionString("MySql"),
        ServerVersion.AutoDetect(builder.Configuration.GetConnectionString("MySql"))
    );
});

var app = builder.Build();
#endregion

#region Home
app.MapGet("/", () => Results.Json(new Home())).AllowAnonymous().WithTags("Home");
#endregion

#region Administradores
string GerarTokenJWt(Administrador administrador){
    if(string.IsNullOrEmpty(key)) return string.Empty;

    var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(key)); 
    var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

    var claims = new List<Claim>()
    {
        new Claim("Email", administrador.Email),
        new Claim("Perfil", administrador.Perfil),
        new Claim(ClaimTypes.Role, administrador.Perfil)

    };

    var token = new JwtSecurityToken(
        claims: claims,
        expires: DateTime.Now.AddDays(1),
        signingCredentials: credentials
    );

    return new JwtSecurityTokenHandler().WriteToken(token);
}

app.MapPost("/administradores/login", ([FromBody] LoginDTO loginDTO, IAdministradorServico administradorServico) => {
    var adm = administradorServico.Login(loginDTO);
    if(adm != null) 
    {
        string token = GerarTokenJWt(adm);

        return Results.Ok(new AdministradorLogado{
            Email = adm.Email,
            Perfil = adm.Perfil,
            Token = token
        });
    }
    else 
        return Results.Unauthorized();
}).AllowAnonymous().WithTags("Administradores");

app.MapPost("/administradores", ([FromBody] AdministradorDTO AdministradorDTO, IAdministradorServico administradorServico) => {

    var validacao = new ErrosDeValidacao{
        Mensagens = new List<string>()
    };

    if(string.IsNullOrEmpty(AdministradorDTO.Email))
        validacao.Mensagens.Add("Email não pode ser vazio");
    if(string.IsNullOrEmpty(AdministradorDTO.Senha))
        validacao.Mensagens.Add("Senha não pode ser vazio");
    if(AdministradorDTO.Perfil == null)
        validacao.Mensagens.Add("Perfil não pode ser vazio");

    if(validacao.Mensagens.Count > 0)
        return Results.BadRequest(validacao);
    
    var administrador = new Administrador {
        Email = AdministradorDTO.Email,
        Senha = AdministradorDTO.Senha,
        Perfil = AdministradorDTO.Perfil.ToString() ?? Perfil.Editor.ToString()
    };

    administradorServico.Incluir(administrador);

    return Results.Created($"/administradores/{administrador.Id}", administrador);
})
.RequireAuthorization()
.RequireAuthorization(new AuthorizeAttribute { Roles = "Adm"})
.WithTags("Administradores");

app.MapGet("/administradores", ([FromQuery] int? pagina, IAdministradorServico administradorServico) => {
    var adms = new List<AdministradorModelView>();
    var administradores = administradorServico.Todos(pagina);
    foreach(var adm in administradores)
    {
        adms.Add(new AdministradorModelView{
            Id = adm.Id,
            Email = adm.Email,
            Perfil = adm.Perfil
        });
    }
    Results.Ok(adms);

})
.RequireAuthorization()
.RequireAuthorization(new AuthorizeAttribute { Roles = "Adm"})
.WithTags("Administradores");

app.MapGet("/administradores/{id}", ([FromRoute] int id, IAdministradorServico administradorServico) => {
    var administrador = administradorServico.BuscaPorId(id);

    if(administrador == null) return Results.NotFound();

    return Results.Ok(new AdministradorModelView{
            Id = administrador.Id,
            Email = administrador.Email,
            Perfil = administrador.Perfil
        });
})
.RequireAuthorization()
.RequireAuthorization(new AuthorizeAttribute { Roles = "Adm"})
.WithTags("Administradores");

    
#endregion

#region Veiculos
    ErrosDeValidacao validaDTO(VeiculoDTO veiculoDTO)
    {
        var validacao = new ErrosDeValidacao{
            Mensagens = new List<string>()
        };

        if(string.IsNullOrEmpty(veiculoDTO.Nome))
            validacao.Mensagens.Add("O nome não pode ser vazio");
        if(string.IsNullOrEmpty(veiculoDTO.Marca))
            validacao.Mensagens.Add("A marca não pode ficar vazia");
        if(veiculoDTO.Ano < 1950)
            validacao.Mensagens.Add("Veículo muito antigo, coloque acima de 1949");

        return validacao;
    } 


    app.MapPost("/veiculos", ([FromBody] VeiculoDTO veiculoDTO, IVeiculoServico veiculoServico) => {
    
        var validacao = validaDTO(veiculoDTO);
        if(validacao.Mensagens.Count > 0)
            return Results.BadRequest(validacao);

        var veiculo = new Veiculo {
            Nome = veiculoDTO.Nome,
            Marca = veiculoDTO.Marca,
            Ano = veiculoDTO.Ano
        };
        veiculoServico.Incluir(veiculo);

        return Results.Created($"/Veiculo/{veiculo.Id}", veiculo);
    })
    .RequireAuthorization()
    .RequireAuthorization(new AuthorizeAttribute { Roles = "Adm,Editor"})
    .WithTags("Veiculos");

    app.MapGet("/veiculos", ([FromQuery] int? pagina, IVeiculoServico veiculoServico) => {
        var veiculos = veiculoServico.Todos(pagina);
    
        return Results.Ok(veiculos);
    })
    .RequireAuthorization()
    .WithTags("Veiculos");

    app.MapGet("/veiculos/{id}", ([FromRoute] int id, IVeiculoServico veiculoServico) => {
        var veiculo = veiculoServico.BuscaPorId(id);
    
        if(veiculo == null) return Results.NotFound();

        return Results.Ok(veiculo);
    })
    .RequireAuthorization()
    .RequireAuthorization(new AuthorizeAttribute { Roles = "Adm,Editor"})
    .WithTags("Veiculos");

    app.MapPut("/veiculos/{id}", ([FromRoute] int id, VeiculoDTO veiculoDTO, IVeiculoServico veiculoServico) => {
        
        var veiculo = veiculoServico.BuscaPorId(id);
        if(veiculo == null) return Results.NotFound();

        var validacao = validaDTO(veiculoDTO);
        if(validacao.Mensagens.Count > 0)
            return Results.BadRequest(validacao);

        veiculo.Nome = veiculoDTO.Nome;
        veiculo.Marca = veiculoDTO.Marca;
        veiculo.Ano = veiculoDTO.Ano;

        veiculoServico.Atualizar(veiculo);

        return Results.Ok(veiculo);
    })
    .RequireAuthorization()
    .RequireAuthorization(new AuthorizeAttribute { Roles = "Adm"})
    .WithTags("Veiculos");

    app.MapDelete("/veiculos/{id}", ([FromRoute] int id, IVeiculoServico veiculoServico) => {
        var veiculo = veiculoServico.BuscaPorId(id);
        if(veiculo == null) return Results.NotFound();

        veiculoServico.Apagar(veiculo);

        return Results.NoContent();
    })
    .RequireAuthorization()
    .WithTags("Veiculos");

#endregion

#region App
app.UseSwagger();
app.UseSwaggerUI();

app.UseAuthentication();
app.UseAuthorization();

app.Run();
#endregion
