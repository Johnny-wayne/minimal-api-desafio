﻿// <auto-generated />
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Metadata;
using Microsoft.EntityFrameworkCore.Migrations;
using Microsoft.EntityFrameworkCore.Storage.ValueConversion;
using MinimalApi.Infraestrutura.Db;

#nullable disable

namespace minimal_api.Migrations
{
    [DbContext(typeof(DbContexto))]
    [Migration("20241105022346_AdministradorMigration")]
    partial class AdministradorMigration
    {
        /// <inheritdoc />
        protected override void BuildTargetModel(ModelBuilder modelBuilder)
        {
#pragma warning disable 612, 618
            modelBuilder
                .HasAnnotation("ProductVersion", "8.0.10")
                .HasAnnotation("Relational:MaxIdentifierLength", 64);

            MySqlModelBuilderExtensions.AutoIncrementColumns(modelBuilder);

            modelBuilder.Entity("minimal_api.Dominio.Entidades.Administrador", b =>
                {
                    b.Property<int>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("int");

                    MySqlPropertyBuilderExtensions.UseMySqlIdentityColumn(b.Property<int>("Id"));

                    b.Property<int>("Email")
                        .HasMaxLength(255)
                        .HasColumnType("int");

                    b.Property<int>("Perfil")
                        .HasMaxLength(10)
                        .HasColumnType("int");

                    b.Property<int>("Senha")
                        .HasMaxLength(50)
                        .HasColumnType("int");

                    b.HasKey("Id");

                    b.ToTable("Administradores");
                });
#pragma warning restore 612, 618
        }
    }
}