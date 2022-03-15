// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.
// Modified by TimCodes.NET

using IdentityModel;
using IdentityServer4.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using IdentityServer4.Configuration;
using System.Text.Json;

namespace IdentityServer4.Extensions
{
    /// <summary>
    /// Extensions for Token
    /// </summary>
    public static class TokenExtensions
    {
        /// <summary>
        /// Create the dictionary that will be used to populate the JWT
        /// </summary>
        /// <param name="token"></param>
        /// <param name="clock"></param>
        /// <param name="options"></param>
        /// <param name="logger"></param>
        /// <returns></returns>
        public static Dictionary<string, object> CreateJwtDictionary(this Token token, ISystemClock clock, IdentityServerOptions options, ILogger logger)
        {
            try
            {
                var now = clock.UtcNow.ToUnixTimeSeconds();
                var exp = now + token.Lifetime;

                var payload = new Dictionary<string, object>
                {
                    { JwtClaimTypes.Issuer, token.Issuer },
                    { JwtClaimTypes.NotBefore, now },
                    { JwtClaimTypes.Expiration, exp }
                };

                if (token.Audiences.Any())
                {
                    if (token.Audiences.Count == 1)
                    {
                        payload.Add(JwtClaimTypes.Audience, token.Audiences.First());
                    }
                    else
                    {
                        payload.Add(JwtClaimTypes.Audience, token.Audiences);
                    }
                }

                if (token.Confirmation.IsPresent())
                {
                    payload.Add(JwtClaimTypes.Confirmation, 
                        JsonSerializer.Deserialize<JsonElement>(token.Confirmation));
                }

                var scopeClaims = token.Claims.Where(x => x.Type == JwtClaimTypes.Scope).ToArray();
                if (!scopeClaims.IsNullOrEmpty())
                {
                    var scopeValues = scopeClaims.Select(x => x.Value).ToArray();

                    if (options.EmitScopesAsSpaceDelimitedStringInJwt)
                    {
                        payload.Add(JwtClaimTypes.Scope, string.Join(" ", scopeValues));
                    }
                    else
                    {
                        payload.Add(JwtClaimTypes.Scope, scopeValues);
                    }
                }

                var amrClaims = token.Claims.Where(x => x.Type == JwtClaimTypes.AuthenticationMethod).ToArray();
                if (!amrClaims.IsNullOrEmpty())
                {
                    var amrValues = amrClaims.Select(x => x.Value).Distinct().ToArray();
                    payload.Add(JwtClaimTypes.AuthenticationMethod, amrValues);
                }

                var distinctClaimTypes = token.Claims.Where(c => 
                        c.Type != JwtClaimTypes.AuthenticationMethod && 
                        c.Type != JwtClaimTypes.Scope)
                    .Select(c => c.Type)
                    .Distinct();

                foreach (var claimType in distinctClaimTypes)
                {
                    var claims = token.Claims.Where(c => c.Type == claimType).ToArray();

                    if (claims.Length == 1)
                    {
                        payload.Add(claimType, claims.First().ToObject());
                    }
                    else
                    {
                        payload.Add(claimType, claims.ToObjectArray());
                    }
                }

                return payload;
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "JWT dictionary could not be created");
                throw;
            }
        }
    }
}