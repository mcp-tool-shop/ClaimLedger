namespace ClaimLedger.Application.Packs;

/// <summary>
/// Validates pack paths for safety.
/// Prevents path traversal attacks and invalid paths.
/// </summary>
public static class PackPathValidator
{
    /// <summary>
    /// Result of path validation.
    /// </summary>
    public sealed class ValidationResult
    {
        public required bool IsValid { get; init; }
        public string? Error { get; init; }

        public static ValidationResult Valid() => new() { IsValid = true };
        public static ValidationResult Invalid(string error) => new() { IsValid = false, Error = error };
    }

    /// <summary>
    /// Validates a pack-relative path for safety.
    /// </summary>
    public static ValidationResult ValidatePath(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return ValidationResult.Invalid("Path cannot be empty");
        }

        // Check for null bytes
        if (path.Contains('\0'))
        {
            return ValidationResult.Invalid("Path contains null byte");
        }

        // Check for absolute paths
        if (Path.IsPathRooted(path))
        {
            return ValidationResult.Invalid("Absolute paths not allowed");
        }

        // Check for drive letters (Windows)
        if (path.Length >= 2 && char.IsLetter(path[0]) && path[1] == ':')
        {
            return ValidationResult.Invalid("Drive letters not allowed");
        }

        // Check for UNC paths
        if (path.StartsWith("\\\\", StringComparison.Ordinal) || path.StartsWith("//", StringComparison.Ordinal))
        {
            return ValidationResult.Invalid("UNC paths not allowed");
        }

        // Split by both forward and back slashes
        var segments = path.Split('/', '\\');

        foreach (var segment in segments)
        {
            // Check for path traversal
            if (segment == "..")
            {
                return ValidationResult.Invalid("Path traversal (..) not allowed");
            }

            // Check for current directory (not strictly necessary but cleaner)
            if (segment == ".")
            {
                return ValidationResult.Invalid("Current directory (.) not allowed in paths");
            }

            // Check for empty segments (double slashes)
            if (string.IsNullOrEmpty(segment))
            {
                // Allow trailing slash but not leading or double
                if (segment != segments[^1])
                {
                    continue; // Skip empty segments from normalization
                }
            }

            // Check for reserved Windows names
            if (IsWindowsReservedName(segment))
            {
                return ValidationResult.Invalid($"Reserved filename not allowed: {segment}");
            }
        }

        return ValidationResult.Valid();
    }

    /// <summary>
    /// Normalizes a path to use forward slashes.
    /// </summary>
    public static string NormalizePath(string path)
    {
        return path.Replace('\\', '/').TrimEnd('/');
    }

    /// <summary>
    /// Combines a base directory with a pack-relative path safely.
    /// Returns null if the resulting path would escape the base directory.
    /// </summary>
    public static string? SafeCombine(string baseDir, string relativePath)
    {
        var validation = ValidatePath(relativePath);
        if (!validation.IsValid)
        {
            return null;
        }

        // Normalize the relative path for the OS
        var normalized = relativePath.Replace('/', Path.DirectorySeparatorChar);

        var combined = Path.Combine(baseDir, normalized);
        var fullPath = Path.GetFullPath(combined);
        var baseFull = Path.GetFullPath(baseDir);

        // Ensure the result is within the base directory
        if (!fullPath.StartsWith(baseFull, StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        return fullPath;
    }

    /// <summary>
    /// Gets the relative path from a base directory, using forward slashes.
    /// </summary>
    public static string GetRelativePath(string baseDir, string fullPath)
    {
        var relative = Path.GetRelativePath(baseDir, fullPath);
        return NormalizePath(relative);
    }

    private static bool IsWindowsReservedName(string name)
    {
        // Remove extension for comparison
        var nameWithoutExt = Path.GetFileNameWithoutExtension(name).ToUpperInvariant();

        return nameWithoutExt switch
        {
            "CON" or "PRN" or "AUX" or "NUL" => true,
            "COM1" or "COM2" or "COM3" or "COM4" or "COM5" or "COM6" or "COM7" or "COM8" or "COM9" => true,
            "LPT1" or "LPT2" or "LPT3" or "LPT4" or "LPT5" or "LPT6" or "LPT7" or "LPT8" or "LPT9" => true,
            _ => false
        };
    }
}
