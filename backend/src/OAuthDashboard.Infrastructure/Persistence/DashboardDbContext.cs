using Microsoft.EntityFrameworkCore;
using OAuthDashboard.Core.Accounts;
using OAuthDashboard.Core.Users;

namespace OAuthDashboard.Infrastructure.Persistence;

/// <summary>
/// SQLite via EF Core — zero-infra and right-sized for a single-user personal dashboard.
/// </summary>
/// <remarks>
/// Worth being clear-eyed about what the database file is and isn't: the token columns hold Data
/// Protection ciphertext (see <c>TokenProtector</c>), so the file on its own is not a credential
/// dump. It is still a list of which providers are linked and when, so it stays out of git.
/// </remarks>
public class DashboardDbContext(DbContextOptions<DashboardDbContext> options) : DbContext(options)
{
    public DbSet<User> Users => Set<User>();

    public DbSet<LinkedAccount> LinkedAccounts => Set<LinkedAccount>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<User>(user =>
        {
            user.HasKey(u => u.Id);
            user.Property(u => u.Username).HasMaxLength(64).IsRequired();
            user.Property(u => u.PasswordHash).IsRequired();

            // Usernames are compared case-insensitively at login, so uniqueness has to be enforced
            // the same way — otherwise "Artturi" and "artturi" are two rows that both answer to one
            // login attempt.
            user.HasIndex(u => u.Username).IsUnique();
        });

        modelBuilder.Entity<LinkedAccount>(account =>
        {
            account.HasKey(a => a.Id);

            // Stored as the enum's name ("GitHub") rather than its number, so the rows stay
            // readable and reordering the enum can't silently repoint tokens at another provider.
            account.Property(a => a.Provider).HasConversion<string>().HasMaxLength(32).IsRequired();

            account.Property(a => a.EncryptedAccessToken).IsRequired();
            account.Property(a => a.ProviderUserId).HasMaxLength(128);
            account.Property(a => a.ProviderAccountName).HasMaxLength(256);
            account.Property(a => a.Scopes).HasMaxLength(512);

            // One link per provider per user: re-linking updates the existing row instead of
            // silently accumulating stale token copies that would each have to be revoked.
            account.HasIndex(a => new { a.UserId, a.Provider }).IsUnique();

            account.HasOne(a => a.User)
                .WithMany(u => u.LinkedAccounts)
                .HasForeignKey(a => a.UserId)
                .OnDelete(DeleteBehavior.Cascade);
        });
    }
}
