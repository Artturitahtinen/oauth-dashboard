using Microsoft.AspNetCore.DataProtection;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using OAuthDashboard.Core.Accounts;
using OAuthDashboard.Core.Users;
using OAuthDashboard.Infrastructure.Accounts;
using OAuthDashboard.Infrastructure.Auth;
using OAuthDashboard.Infrastructure.Persistence;
using OAuthDashboard.Infrastructure.Security;

namespace OAuthDashboard.Tests;

/// <summary>
/// Exercises the round trip that M2 exists to prove: a provider token goes into SQLite as
/// ciphertext and comes back out usable. Runs against a real SQLite database (in-memory, but the
/// actual provider — not the EF in-memory provider), so the column types and unique indexes from
/// the migration are genuinely in play.
/// </summary>
public class TokenPersistenceTests : IAsyncLifetime
{
    private const string AccessToken = "gho_pretend-this-came-from-github";
    private const string RefreshToken = "ghr_pretend-refresh-token";

    // Held open deliberately: a SQLite in-memory database exists only as long as a connection to it
    // does, so closing this would drop the schema mid-test.
    private SqliteConnection _connection = null!;
    private DashboardDbContext _db = null!;
    private LinkedAccountService _service = null!;
    private int _userId;

    public async Task InitializeAsync()
    {
        _connection = new SqliteConnection("Data Source=:memory:");
        await _connection.OpenAsync();

        _db = new DashboardDbContext(
            new DbContextOptionsBuilder<DashboardDbContext>().UseSqlite(_connection).Options);
        await _db.Database.EnsureCreatedAsync();

        var protector = new TokenProtector(new EphemeralDataProtectionProvider());
        _service = new LinkedAccountService(_db, protector);

        var user = new User
        {
            Username = "tester",
            PasswordHash = PasswordHasher.Hash("a-long-enough-password"),
            CreatedAtUtc = DateTimeOffset.UtcNow,
        };
        _db.Users.Add(user);
        await _db.SaveChangesAsync();
        _userId = user.Id;
    }

    public async Task DisposeAsync()
    {
        await _db.DisposeAsync();
        await _connection.DisposeAsync();
    }

    [Fact]
    public async Task UpsertAsync_StoresATokenThatCanBeReadBack()
    {
        await UpsertAsync(AccessToken, RefreshToken);

        var recovered = await _service.GetAccessTokenAsync(_userId, OAuthProvider.GitHub, CancellationToken.None);

        Assert.Equal(AccessToken, recovered);
    }

    /// <summary>
    /// The central claim of "encrypted at rest": reading the column directly must not yield the
    /// token. Without this assertion every other test here would pass just as happily against a
    /// protector that returned its input unchanged.
    /// </summary>
    [Fact]
    public async Task UpsertAsync_WritesCiphertextNotPlaintext()
    {
        await UpsertAsync(AccessToken, RefreshToken);

        var stored = await _db.LinkedAccounts.AsNoTracking()
            .SingleAsync(a => a.UserId == _userId, CancellationToken.None);

        Assert.NotEqual(AccessToken, stored.EncryptedAccessToken);
        Assert.DoesNotContain(AccessToken, stored.EncryptedAccessToken, StringComparison.Ordinal);
        Assert.NotNull(stored.EncryptedRefreshToken);
        Assert.DoesNotContain(RefreshToken, stored.EncryptedRefreshToken, StringComparison.Ordinal);
    }

    /// <summary>
    /// Re-linking updates the existing row. A second row would mean a stale token copy that
    /// revocation (M5) would never find.
    /// </summary>
    [Fact]
    public async Task UpsertAsync_ReplacesTheExistingLinkRatherThanAddingASecond()
    {
        await UpsertAsync(AccessToken, RefreshToken);
        await UpsertAsync("gho_rotated", "ghr_rotated");

        var rows = await _db.LinkedAccounts.AsNoTracking()
            .Where(a => a.UserId == _userId).ToListAsync(CancellationToken.None);

        Assert.Single(rows);
        Assert.Equal("gho_rotated", await _service.GetAccessTokenAsync(_userId, OAuthProvider.GitHub, CancellationToken.None));
    }

    /// <summary>
    /// Google omits <c>refresh_token</c> on repeat consents. If a re-link overwrote the stored value
    /// with null, M3's refresh path would break silently and only show up as a forced re-link days
    /// later — so a null refresh token has to leave the good stored one alone.
    /// </summary>
    [Fact]
    public async Task UpsertAsync_KeepsTheStoredRefreshTokenWhenTheProviderOmitsIt()
    {
        await UpsertAsync(AccessToken, RefreshToken);
        var before = await StoredRefreshCiphertextAsync();

        await UpsertAsync("gho_second-consent", refreshToken: null);
        var after = await StoredRefreshCiphertextAsync();

        Assert.NotNull(after);
        Assert.Equal(before, after);
    }

    [Fact]
    public async Task GetAccessTokenAsync_ReturnsNullForAnUnlinkedProvider()
    {
        await UpsertAsync(AccessToken, RefreshToken);

        Assert.Null(await _service.GetAccessTokenAsync(_userId, OAuthProvider.Google, CancellationToken.None));
    }

    /// <summary>
    /// The SPA-facing projection must carry no token material at all, encrypted or otherwise.
    /// </summary>
    [Fact]
    public async Task GetSummariesAsync_ExposesNoTokenMaterial()
    {
        await UpsertAsync(AccessToken, RefreshToken);

        var summaries = await _service.GetSummariesAsync(_userId, CancellationToken.None);

        var summary = Assert.Single(summaries);
        Assert.Equal("GitHub", summary.Provider);
        Assert.Equal("octocat", summary.AccountName);

        var serialized = System.Text.Json.JsonSerializer.Serialize(summary);
        Assert.DoesNotContain(AccessToken, serialized, StringComparison.Ordinal);
        Assert.DoesNotContain(RefreshToken, serialized, StringComparison.Ordinal);
    }

    [Fact]
    public async Task DeleteAsync_RemovesTheLinkAndReportsWhetherThereWasOne()
    {
        await UpsertAsync(AccessToken, RefreshToken);

        Assert.True(await _service.DeleteAsync(_userId, OAuthProvider.GitHub, CancellationToken.None));
        Assert.Null(await _service.GetAccessTokenAsync(_userId, OAuthProvider.GitHub, CancellationToken.None));
        Assert.False(await _service.DeleteAsync(_userId, OAuthProvider.GitHub, CancellationToken.None));
    }

    /// <summary>
    /// A token issued with no advertised expiry must stay null rather than collapsing to a past
    /// date — M3 branches on exactly this distinction.
    /// </summary>
    [Fact]
    public async Task UpsertAsync_PreservesAMissingExpiryAsNull()
    {
        await UpsertAsync(AccessToken, RefreshToken, expiresAtUtc: null);

        var summary = Assert.Single(await _service.GetSummariesAsync(_userId, CancellationToken.None));
        Assert.Null(summary.ExpiresAtUtc);
    }

    private Task UpsertAsync(string accessToken, string? refreshToken, DateTimeOffset? expiresAtUtc = null) =>
        _service.UpsertAsync(
            _userId,
            OAuthProvider.GitHub,
            new OAuthTokenResult(accessToken, refreshToken, "read:user", expiresAtUtc),
            new ProviderAccountInfo("583231", "octocat"),
            CancellationToken.None);

    private async Task<string?> StoredRefreshCiphertextAsync() =>
        (await _db.LinkedAccounts.AsNoTracking()
            .SingleAsync(a => a.UserId == _userId, CancellationToken.None))
        .EncryptedRefreshToken;
}
