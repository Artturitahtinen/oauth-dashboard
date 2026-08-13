namespace OAuthDashboard.Infrastructure.Auth;

/// <summary>
/// The minimum a provider tells us about the account that was just linked: a stable id and a
/// display handle. Only these two are persisted — the full profile JSON is fetched on demand rather
/// than mirrored into the local database, so there's less of the user's data sitting at rest than
/// strictly necessary.
/// </summary>
public record ProviderAccountInfo(string Id, string DisplayName);
