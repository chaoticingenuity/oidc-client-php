<?php
/*
 * Copyright © 2023 Maicol07 (https://maicol07.it)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may get a copy of the License at
 *
 *             http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License
 * is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific language governing permissions and
 * limitations under the License.
 */

namespace Maicol07\OpenIDConnect;

enum Scope: string
{
    case OPENID = 'openid'; /** Indicates the openid scope. See: https://openid.net/specs/openid-connect-core-1_0.html#ScopeClaims. */
    case PROFILE = 'profile'; /** Indicates the profile scope. See: https://openid.net/specs/openid-connect-core-1_0.html#ScopeClaims. */
    case OPENID_PROFILE = 'openid profile'; /** Indicates both openid and profile scopes. See: https://openid.net/specs/openid-connect-core-1_0.html#ScopeClaims. */
    case EMAIL = 'email'; /** Indicates the email scope. See: https://openid.net/specs/openid-connect-core-1_0.html#ScopeClaims. */
    case ADDRESS = 'address'; /** Indicates the address scope. See: https://openid.net/specs/openid-connect-core-1_0.html#ScopeClaims. */
    case PHONE = 'phone'; /** Indicates the phone scope. See: https://openid.net/specs/openid-connect-core-1_0.html#ScopeClaims. */
    case OFFLINE_ACCESS = 'offline_access'; /** Indicates the offline_access scope. See: https://openid.net/specs/openid-connect-core-1_0.html#ScopeClaims. */
    case GROUPS = 'groups';
    case USER_IMPERSONATION = 'user_impersonation'; /** Indicates the user_impersonation scope for Microsoft Entra ID. */
}
