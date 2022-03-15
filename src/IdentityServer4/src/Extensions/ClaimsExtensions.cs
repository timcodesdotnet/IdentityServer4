// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.
// Modified by TimCodes.NET

using IdentityModel;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text.Json;

namespace IdentityServer4.Extensions
{
    internal static class ClaimsExtensions
    {
        public static Dictionary<string, object> ToClaimsDictionary(this IEnumerable<Claim> claims)
        {
            var d = new Dictionary<string, object>();

            if (claims == null)
            {
                return d;
            }

            var distinctClaims = claims.Distinct(new ClaimComparer());

            foreach (var claim in distinctClaims)
            {
                if (!d.ContainsKey(claim.Type))
                {
                    d.Add(claim.Type, GetValue(claim));
                }
                else
                {
                    var value = d[claim.Type];

                    if (value is List<object> list)
                    {
                        list.Add(GetValue(claim));
                    }
                    else
                    {
                        d.Remove(claim.Type);
                        d.Add(claim.Type, new List<object> { value, GetValue(claim) });
                    }
                }
            }

            return d;
        }

        public static IEnumerable<object> ToObjectArray(this IEnumerable<Claim> claims)
            => claims.Select(q => ToObject(q));

        public static object ToObject(this Claim claim)
        {
            return claim.Type switch
            {
                ClaimValueTypes.Boolean
                    => bool.Parse(claim.Value),
                ClaimValueTypes.Integer or ClaimValueTypes.Integer32
                    => int.Parse(claim.Value),
                ClaimValueTypes.Integer64
                    => long.Parse(claim.Value),
                ClaimValueTypes.Double
                    => double.Parse(claim.Value),
                ClaimValueTypes.UInteger32
                    => uint.Parse(claim.Value),
                ClaimValueTypes.UInteger64
                    => ulong.Parse(claim.Value),
                IdentityServerConstants.ClaimValueTypes.Json
                    => JsonSerializer.Deserialize<JsonElement>(claim.Value),
                _ => claim.Value,
            };
        }

        private static object GetValue(Claim claim)
        {
            if (claim.ValueType == ClaimValueTypes.Integer ||
                claim.ValueType == ClaimValueTypes.Integer32)
            {
                if (Int32.TryParse(claim.Value, out int value))
                {
                    return value;
                }
            }

            if (claim.ValueType == ClaimValueTypes.Integer64)
            {
                if (Int64.TryParse(claim.Value, out long value))
                {
                    return value;
                }
            }

            if (claim.ValueType == ClaimValueTypes.Boolean)
            {
                if (bool.TryParse(claim.Value, out bool value))
                {
                    return value;
                }
            }

            if (claim.ValueType == IdentityServerConstants.ClaimValueTypes.Json)
            {
                try
                {
                    return System.Text.Json.JsonSerializer.Deserialize<JsonElement>(claim.Value);
                }
                catch { }
            }

            return claim.Value;
        }
    }
}