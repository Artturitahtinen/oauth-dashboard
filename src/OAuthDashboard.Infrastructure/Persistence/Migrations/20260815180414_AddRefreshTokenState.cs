using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace OAuthDashboard.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class AddRefreshTokenState : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<DateTimeOffset>(
                name: "ReauthorizationRequiredAtUtc",
                table: "LinkedAccounts",
                type: "TEXT",
                nullable: true);

            migrationBuilder.AddColumn<DateTimeOffset>(
                name: "RefreshTokenExpiresAtUtc",
                table: "LinkedAccounts",
                type: "TEXT",
                nullable: true);

            migrationBuilder.AddColumn<DateTimeOffset>(
                name: "RefreshedAtUtc",
                table: "LinkedAccounts",
                type: "TEXT",
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "ReauthorizationRequiredAtUtc",
                table: "LinkedAccounts");

            migrationBuilder.DropColumn(
                name: "RefreshTokenExpiresAtUtc",
                table: "LinkedAccounts");

            migrationBuilder.DropColumn(
                name: "RefreshedAtUtc",
                table: "LinkedAccounts");
        }
    }
}
