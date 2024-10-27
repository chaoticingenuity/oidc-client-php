<?php
/*
 * Copyright © 2024 Maicol07 (https://maicol07.it)
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

/** @noinspection PhpUnusedPrivateMethodInspection */

namespace Maicol07\OpenIDConnect\Traits;

use cse\helpers\Session;
use Exception;
use Illuminate\Http\Client\ConnectionException;
use \Firebase\JWT\JWT as FirebaseJWT;
use \Firebase\JWT\JWK as FirebaseJWK;
use Jose\Component\Checker;
use Jose\Component\Checker\AlgorithmChecker;
use Jose\Component\Checker\ClaimCheckerManager;
use Jose\Component\Checker\HeaderCheckerManager;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWKSet;
use Jose\Component\Signature\JWS;
use Jose\Component\Signature\JWSLoader;
use Jose\Component\Signature\JWSTokenSupport;
use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Signature\Serializer\CompactSerializer;
use Jose\Component\Signature\Serializer\JWSSerializerManager;
use JsonException;
use Maicol07\OpenIDConnect\Checker\NonceChecker;
use Maicol07\OpenIDConnect\JwtSigningAlgorithm;
use Maicol07\OpenIDConnect\OIDCClientException;
use SensitiveParameter;
use Symfony\Component\Clock\NativeClock;

trait JWT
{
    /**
     * Loads and validates a JWT
     *
     * @throws JsonException If the JWT payload is not valid JSON
     * @throws Exception If the JWT is not valid
     */
    private function loadAndValidateJWT(#[SensitiveParameter] string $jwt): JWS
    {
        $clock = new NativeClock();
        $claimCheckerManager = new ClaimCheckerManager(
            [
                new Checker\IssuedAtChecker($clock, $this->time_drift),
                new Checker\NotBeforeChecker($clock, $this->time_drift),
                new Checker\ExpirationTimeChecker($clock, $this->time_drift),
                new Checker\AudienceChecker($this->client_id),
                new Checker\IssuerChecker([$this->issuer])
            ]
        );



        $jwt_parts = explode('.', $jwt);

        $jwt_header = json_decode(base64_decode(str_replace('_', '/', str_replace('-', '+', $jwt_parts[0]))), true, 512, JSON_THROW_ON_ERROR);

        $jwt_header_kid = $jwt_header['kid'];

        $jwt_payload = json_decode(base64_decode(str_replace('_', '/', str_replace('-', '+', $jwt_parts[1]))), true, 512, JSON_THROW_ON_ERROR);

        if ($jwt_payload['iss'] !== $this->issuer) {
            throw new OIDCClientException('Error: validation of iss response parameter failed');
        }

        // $id_token_signature = base64_decode(str_replace('_', '/', str_replace('-', '+', $jwt_parts[2])));

        $oidc__jwks = $this->getRAWJWKs();
        $oidc__jwks_key = array_values(array_filter($oidc__jwks['keys'], fn($e) => $e['kid'] === $jwt_header_kid))[0] ?? null;

        FirebaseJWT::$leeway = 60; // $leeway in seconds
        $keyset = FirebaseJWK::parseKeySet(['keys' => [$oidc__jwks_key]]);
        try {
            $decoded = FirebaseJWT::decode($jwt, $keyset);

            /** @noinspection UnusedFunctionResultInspection */
            $claimCheckerManager->check($jwt_payload);

            Session::remove('oidc_nonce');

            return $this->jwsLoader()->getSerializerManager()->unserialize($jwt);
        } catch (\Firebase\JWT\SignatureInvalidException | Exception $e) {
            $decoded = null;

            throw new Exception('Unable to load and verify the token.');
        }



        $jws = $this->jwsLoader()->loadAndVerifyWithKeySet($jwt, $this->getJWKs(), $signature);
        /** @noinspection UnusedFunctionResultInspection */
        $claimCheckerManager->check(json_decode($jws->getPayload(), true, 512, JSON_THROW_ON_ERROR));
        Session::remove('oidc_nonce');

        return $jws;
    }

    /**
     * Creates a JWS Loader
     */
    private function jwsLoader(): JWSLoader
    {
        $algorithmManager = new AlgorithmManager(array_map(static fn(JwtSigningAlgorithm $algorithm): \Jose\Component\Core\Algorithm => $algorithm->getAlgorithmObject(), $this->id_token_signing_alg_values_supported));
        $checkers = [
            new AlgorithmChecker(array_map(static fn(JwtSigningAlgorithm $algorithm) => $algorithm->name, $this->id_token_signing_alg_values_supported))
        ];
        if ($this->enable_nonce) {
            $checkers[] = new NonceChecker(Session::get('oidc_nonce'));
        }
        $headerChecker = new HeaderCheckerManager($checkers, [new JWSTokenSupport()]);

        // We instantiate our JWS Verifier.
        $jwsVerifier = new JWSVerifier(
            $algorithmManager
        );

        // The serializer manager. We only use the JWS Compact Serialization Mode.
        $serializerManager = new JWSSerializerManager([
            new CompactSerializer(),
        ]);
        return new JWSLoader(
            $serializerManager,
            $jwsVerifier,
            $headerChecker
        );
    }

    /**
     * Gets the JWKs from the JWKS endpoint (if set) or from the JWKs property (if set)
     * @throws ConnectionException
     */
    private function getJWKs(): JWKSet
    {
        if ($this->jwks_endpoint && empty($this->jwks)) {
            $set = $this->client()->get($this->jwks_endpoint)->json();
            $this->jwks = JWKSet::createFromKeyData($set);
        }

        return $this->jwks;
    }
    /**
     * Gets the raw array of jwks from the JWKS endpoint (if set) or null
     * @todo ( or from the JWKs property (if set) ) should determine function to retrieve raw from stored prop
     * @throws ConnectionException
     */
    private function getRAWJWKs(): array|null
    {
        if ($this->jwks_endpoint/** && empty($this->jwks) */) {
            return $this->client()->get($this->jwks_endpoint)->json();
        }

        return null;
    }
}
