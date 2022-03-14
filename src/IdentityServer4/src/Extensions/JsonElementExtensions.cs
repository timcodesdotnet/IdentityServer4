using System.Text.Json;

namespace IdentityServer4.Extensions;

/// <summary>
/// Extensions to enable converting to object
/// </summary>
public static class JsonElementExtensions
{
    /// <summary>
    /// Convert to custom type
    /// </summary>
    /// <typeparam name="T"></typeparam>
    /// <param name="element"></param>
    /// <returns></returns>
    public static T ToObject<T>(this JsonElement element)
    {
        var json = element.GetRawText();
        return JsonSerializer.Deserialize<T>(json);
    }

    /// <summary>
    /// Convert to custom type
    /// </summary>
    /// <typeparam name="T"></typeparam>
    /// <param name="document"></param>
    /// <returns></returns>
    public static T ToObject<T>(this JsonDocument document)
    {
        var json = document.RootElement.GetRawText();
        return JsonSerializer.Deserialize<T>(json);
    }
}
