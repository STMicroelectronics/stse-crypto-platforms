/******************************************************************************
 * \file	stse_platform_ecc.c
 * \brief   STSecureElement ECC platform file
 * \author  STMicroelectronics - CS application team
 *
 ******************************************************************************
 * \attention
 *
 * <h2><center>&copy; COPYRIGHT 2022 STMicroelectronics</center></h2>
 *
 * This software is licensed under terms that can be found in the LICENSE file in
 * the root directory of this software component.
 * If no LICENSE file comes with this software, it is provided AS-IS.
 *
 ******************************************************************************
 */

/* Includes ------------------------------------------------------------------*/
#include <string.h>

#include "Middleware/STM32_Cryptographic/include/cmox_crypto.h"
#include "stse_conf.h"
#include "stselib.h"

cmox_ecc_handle_t ecc_ctx;
#define CMOX_MATH_BUFFER_SIZE 2400u
#define STSE_ECC_RANDOM_BUFFER_MAX 128u
/* CMOX ECC math buffer must be naturally aligned for internal word accesses. */
PLAT_UI64 cmox_math_buffer[(CMOX_MATH_BUFFER_SIZE + sizeof(PLAT_UI64) - 1u) / sizeof(PLAT_UI64)];

#ifdef STSE_CONF_ECC_CURVE_25519
static const uint8_t curve25519_base_point[CMOX_ECC_CURVE25519_PUBKEY_LEN] = {0x09};
#endif /* STSE_CONF_ECC_CURVE_25519 */

static void stse_platform_fill_random_bytes(PLAT_UI8 *p_buffer, size_t length)
{
    size_t offset = 0u;

    while (offset < length)
    {
        PLAT_UI32 rnd = stse_platform_generate_random();
        size_t remaining = length - offset;
        size_t chunk = (remaining < sizeof(rnd)) ? remaining : sizeof(rnd);
        memcpy(&p_buffer[offset], &rnd, chunk);
        offset += chunk;
    }
}

static cmox_ecc_impl_t stse_platform_get_cmox_ecc_impl(stse_ecc_key_type_t key_type)
{
    switch (key_type)
    {
#ifdef STSE_CONF_ECC_NIST_P_256
    case STSE_ECC_KT_NIST_P_256:
        return CMOX_ECC_SECP256R1_LOWMEM;
#endif
#ifdef STSE_CONF_ECC_NIST_P_384
    case STSE_ECC_KT_NIST_P_384:
        return CMOX_ECC_SECP384R1_LOWMEM;
#endif
#ifdef STSE_CONF_ECC_NIST_P_521
    case STSE_ECC_KT_NIST_P_521:
        return CMOX_ECC_SECP521R1_LOWMEM;
#endif
#ifdef STSE_CONF_ECC_BRAINPOOL_P_256
    case STSE_ECC_KT_BP_P_256:
        return CMOX_ECC_BPP256R1_LOWMEM;
#endif
#ifdef STSE_CONF_ECC_BRAINPOOL_P_384
    case STSE_ECC_KT_BP_P_384:
        return CMOX_ECC_BPP384R1_LOWMEM;
#endif
#ifdef STSE_CONF_ECC_BRAINPOOL_P_512
    case STSE_ECC_KT_BP_P_512:
        return CMOX_ECC_BPP512R1_LOWMEM;
#endif
#ifdef STSE_CONF_ECC_CURVE_25519
    case STSE_ECC_KT_CURVE25519:
        return CMOX_ECC_CURVE25519;
#endif
#ifdef STSE_CONF_ECC_EDWARD_25519
    case STSE_ECC_KT_ED25519:
        return CMOX_ECC_ED25519_OPT_LOWMEM;
#endif
    default:
        return NULL;
    }
}

static size_t stse_platform_get_cmox_ecc_pub_key_len(stse_ecc_key_type_t key_type)
{
    switch (key_type)
    {
#ifdef STSE_CONF_ECC_NIST_P_256
    case STSE_ECC_KT_NIST_P_256:
        return CMOX_ECC_SECP256R1_PUBKEY_LEN;
#endif
#ifdef STSE_CONF_ECC_NIST_P_384
    case STSE_ECC_KT_NIST_P_384:
        return CMOX_ECC_SECP384R1_PUBKEY_LEN;
#endif
#ifdef STSE_CONF_ECC_NIST_P_521
    case STSE_ECC_KT_NIST_P_521:
        return CMOX_ECC_SECP521R1_PUBKEY_LEN;
#endif
#ifdef STSE_CONF_ECC_BRAINPOOL_P_256
    case STSE_ECC_KT_BP_P_256:
        return CMOX_ECC_BPP256R1_PUBKEY_LEN;
#endif
#ifdef STSE_CONF_ECC_BRAINPOOL_P_384
    case STSE_ECC_KT_BP_P_384:
        return CMOX_ECC_BPP384R1_PUBKEY_LEN;
#endif
#ifdef STSE_CONF_ECC_BRAINPOOL_P_512
    case STSE_ECC_KT_BP_P_512:
        return CMOX_ECC_BPP512R1_PUBKEY_LEN;
#endif
#ifdef STSE_CONF_ECC_CURVE_25519
    case STSE_ECC_KT_CURVE25519:
        return CMOX_ECC_CURVE25519_PUBKEY_LEN;
#endif
#ifdef STSE_CONF_ECC_EDWARD_25519
    case STSE_ECC_KT_ED25519:
        return CMOX_ECC_ED25519_PUBKEY_LEN;
#endif
    default:
        return 0u;
    }
}

static size_t stse_platform_get_cmox_ecc_sig_len(stse_ecc_key_type_t key_type)
{
    switch (key_type)
    {
#ifdef STSE_CONF_ECC_NIST_P_256
    case STSE_ECC_KT_NIST_P_256:
        return CMOX_ECC_SECP256R1_SIG_LEN;
#endif
#ifdef STSE_CONF_ECC_NIST_P_384
    case STSE_ECC_KT_NIST_P_384:
        return CMOX_ECC_SECP384R1_SIG_LEN;
#endif
#ifdef STSE_CONF_ECC_NIST_P_521
    case STSE_ECC_KT_NIST_P_521:
        return CMOX_ECC_SECP521R1_SIG_LEN;
#endif
#ifdef STSE_CONF_ECC_BRAINPOOL_P_256
    case STSE_ECC_KT_BP_P_256:
        return CMOX_ECC_BPP256R1_SIG_LEN;
#endif
#ifdef STSE_CONF_ECC_BRAINPOOL_P_384
    case STSE_ECC_KT_BP_P_384:
        return CMOX_ECC_BPP384R1_SIG_LEN;
#endif
#ifdef STSE_CONF_ECC_BRAINPOOL_P_512
    case STSE_ECC_KT_BP_P_512:
        return CMOX_ECC_BPP512R1_SIG_LEN;
#endif
#ifdef STSE_CONF_ECC_CURVE_25519
    case STSE_ECC_KT_CURVE25519:
        return STSE_OK; /* No signature with curve25519 */
#endif
#ifdef STSE_CONF_ECC_EDWARD_25519
    case STSE_ECC_KT_ED25519:
        return CMOX_ECC_ED25519_SIG_LEN;
#endif
    default:
        return 0u;
    }
}

static size_t stse_platform_get_cmox_ecc_priv_key_len(stse_ecc_key_type_t key_type)
{
    switch (key_type)
    {
#ifdef STSE_CONF_ECC_NIST_P_256
    case STSE_ECC_KT_NIST_P_256:
        return CMOX_ECC_SECP256R1_PRIVKEY_LEN;
#endif
#ifdef STSE_CONF_ECC_NIST_P_384
    case STSE_ECC_KT_NIST_P_384:
        return CMOX_ECC_SECP384R1_PRIVKEY_LEN;
#endif
#ifdef STSE_CONF_ECC_NIST_P_521
    case STSE_ECC_KT_NIST_P_521:
        return CMOX_ECC_SECP521R1_PRIVKEY_LEN;
#endif
#ifdef STSE_CONF_ECC_BRAINPOOL_P_256
    case STSE_ECC_KT_BP_P_256:
        return CMOX_ECC_BPP256R1_PRIVKEY_LEN;
#endif
#ifdef STSE_CONF_ECC_BRAINPOOL_P_384
    case STSE_ECC_KT_BP_P_384:
        return CMOX_ECC_BPP384R1_PRIVKEY_LEN;
#endif
#ifdef STSE_CONF_ECC_BRAINPOOL_P_512
    case STSE_ECC_KT_BP_P_512:
        return CMOX_ECC_BPP512R1_PRIVKEY_LEN;
#endif
#ifdef STSE_CONF_ECC_CURVE_25519
    case STSE_ECC_KT_CURVE25519:
        return CMOX_ECC_CURVE25519_PRIVKEY_LEN;
#endif
#ifdef STSE_CONF_ECC_EDWARD_25519
    case STSE_ECC_KT_ED25519:
        return CMOX_ECC_ED25519_PRIVKEY_LEN;
#endif
    default:
        return 0u;
    }
}

stse_return_code_t stse_platform_ecc_verify(
    stse_ecc_key_type_t key_type,
    const PLAT_UI8 *p_pub_key,
    PLAT_UI8 *p_digest,
    PLAT_UI16 digest_len,
    PLAT_UI8 *p_signature)
{
#if defined(STSE_CONF_ECC_NIST_P_256) || defined(STSE_CONF_ECC_NIST_P_384) || defined(STSE_CONF_ECC_NIST_P_521) ||                \
    defined(STSE_CONF_ECC_BRAINPOOL_P_256) || defined(STSE_CONF_ECC_BRAINPOOL_P_384) || defined(STSE_CONF_ECC_BRAINPOOL_P_512) || \
    defined(STSE_CONF_ECC_CURVE_25519) || defined(STSE_CONF_ECC_EDWARD_25519)
    cmox_ecc_retval_t retval;
    PLAT_UI32 faultCheck;
    size_t pubKeyLen;
    size_t sigLen;
    cmox_ecc_impl_t curve;

    curve = stse_platform_get_cmox_ecc_impl(key_type);
    pubKeyLen = stse_platform_get_cmox_ecc_pub_key_len(key_type);
    sigLen = stse_platform_get_cmox_ecc_sig_len(key_type);

    if ((p_pub_key == NULL) || (p_digest == NULL) || (p_signature == NULL) ||
        (key_type >= STSE_ECC_KT_INVALID) || (digest_len == 0u) ||
        (curve == NULL) || (pubKeyLen == 0u) || (sigLen == 0u))
    {
        return STSE_PLATFORM_INVALID_PARAMETER;
    }

    /*- Set ECC context */
    cmox_ecc_construct(&ecc_ctx,                     /* ECC context */
                       CMOX_MATH_FUNCS_SMALL,        /* Small math functions */
                       (PLAT_UI8 *)cmox_math_buffer, /* Crypto math buffer */
                       CMOX_MATH_BUFFER_SIZE);       /* buffer size */

#ifdef STSE_CONF_ECC_EDWARD_25519
    if (key_type == STSE_ECC_KT_ED25519)
    {
        /* - Perform EDDSA verify */
        retval = cmox_eddsa_verify(&ecc_ctx,     /* ECC context */
                                   curve,        /* Curve param */
                                   p_pub_key,    /* Public key */
                                   pubKeyLen,    /* Public key length */
                                   p_digest,     /* Message */
                                   digest_len,   /* Message length */
                                   p_signature,  /* Pointer to signature */
                                   sigLen,       /* Signature size */
                                   &faultCheck); /* Fault check variable */
    }
    else
#endif /* STSE_CONF_ECC_EDWARD_25519 || STSE_CONF_ECC_EDWARD_448 */
    {
        /* - Perform ECDSA verify */
        retval = cmox_ecdsa_verify(&ecc_ctx,     /* ECC context */
                                   curve,        /* Curve : SECP256R1 */
                                   p_pub_key,    /* Public key */
                                   pubKeyLen,    /* Public key length */
                                   p_digest,     /* Message */
                                   digest_len,   /* Message length */
                                   p_signature,  /* Pointer to signature */
                                   sigLen,       /* Signature size */
                                   &faultCheck); /* Fault check variable */
     }

    /* - Clear ECC context */
    cmox_ecc_cleanup(&ecc_ctx);

    if (retval != CMOX_ECC_AUTH_SUCCESS)
    {
        return STSE_PLATFORM_ECC_VERIFY_ERROR;
    }

    return STSE_OK;
#else
    return STSE_PLATFORM_ECC_VERIFY_ERROR;
#endif /* STSE_CONF_ECC_NIST_P_256 || STSE_CONF_ECC_NIST_P_384 || STSE_CONF_ECC_NIST_P_521 ||\
          STSE_CONF_ECC_BRAINPOOL_P_256 || STSE_CONF_ECC_BRAINPOOL_P_384 || STSE_CONF_ECC_BRAINPOOL_P_512 ||\
          STSE_CONF_ECC_CURVE_25519 || STSE_CONF_ECC_EDWARD_25519 */
}

stse_return_code_t stse_platform_ecc_generate_key_pair(
    stse_ecc_key_type_t key_type,
    PLAT_UI8 *p_priv_key,
    PLAT_UI8 *p_pub_key)
{
#if defined(STSE_CONF_ECC_NIST_P_256) || defined(STSE_CONF_ECC_NIST_P_384) || defined(STSE_CONF_ECC_NIST_P_521) ||                \
    defined(STSE_CONF_ECC_BRAINPOOL_P_256) || defined(STSE_CONF_ECC_BRAINPOOL_P_384) || defined(STSE_CONF_ECC_BRAINPOOL_P_512) || \
    defined(STSE_CONF_ECC_CURVE_25519) || defined(STSE_CONF_ECC_EDWARD_25519)
    cmox_ecc_retval_t retval;
    PLAT_UI8 random_number[STSE_ECC_RANDOM_BUFFER_MAX];
#if defined(STSE_CONF_ECC_CURVE_25519)
    size_t pub_key_len = stse_platform_get_cmox_ecc_pub_key_len(key_type);;
#endif

    if ((p_priv_key == NULL) || (p_pub_key == NULL) || (key_type >= STSE_ECC_KT_INVALID) ||
        (stse_platform_get_cmox_ecc_impl(key_type) == NULL) ||
        (stse_platform_get_cmox_ecc_priv_key_len(key_type) == 0u))
    {
        return STSE_PLATFORM_INVALID_PARAMETER;
    }

    /*- Set ECC context */
    cmox_ecc_construct(&ecc_ctx,                     /* ECC context */
                       CMOX_MATH_FUNCS_SMALL,        /* Small math functions */
                       (PLAT_UI8 *)cmox_math_buffer, /* Crypto math buffer */
                       CMOX_MATH_BUFFER_SIZE);       /* buffer size */

    /* Minimum random length equal the private key length */
    size_t random_len = stse_platform_get_cmox_ecc_priv_key_len(key_type);

    /* Align the random length to modulo 4 */
    random_len += (4u - (random_len & 0x3u)) & 0x3u;

    if ((random_len == 0u) || (random_len > (sizeof(random_number)/sizeof(random_number[0]))))
    {
        return STSE_PLATFORM_ECC_GENERATE_KEY_PAIR_ERROR;
    }

    /* Retry loop in case the RNG isn't strong enough */
    do
    {
        /* - Generate a random number */
        stse_platform_fill_random_bytes(random_number, random_len);

        /*- Generate EdDSA key pair */
#ifdef STSE_CONF_ECC_EDWARD_25519
        if (key_type == STSE_ECC_KT_ED25519)
        {
            retval = cmox_eddsa_keyGen(&ecc_ctx,                                  /* ECC context */
                                       stse_platform_get_cmox_ecc_impl(key_type), /* Curve param */
                                       random_number,                             /* Random number */
                                       random_len,                                /* Random number length */
                                       p_priv_key,                                /* Private key */
                                       NULL,                                      /* Private key length*/
                                       p_pub_key,                                 /* Public key */
                                       NULL);                                     /* Public key length */
        }
        else
#endif /* STSE_CONF_ECC_EDWARD_25519 */
#ifdef STSE_CONF_ECC_CURVE_25519
        if (key_type == STSE_ECC_KT_CURVE25519)
        {
            retval = cmox_ecdh(&ecc_ctx,
                               CMOX_ECC_CURVE25519,
                               p_priv_key, CMOX_ECC_CURVE25519_PRIVKEY_LEN,
                               curve25519_base_point, sizeof(curve25519_base_point),
                               p_pub_key, &pub_key_len);
        }
        else
#endif /* STSE_CONF_ECC_CURVE_25519 */
        {
            retval = cmox_ecdsa_keyGen(&ecc_ctx,                                  /* ECC context */
                                       stse_platform_get_cmox_ecc_impl(key_type), /* Curve param */
                                       random_number,                             /* Random number */
                                       random_len,                                /* Random number length */
                                       p_priv_key,                                /* Private key */
                                       NULL,                                      /* Private key length*/
                                       p_pub_key,                                 /* Public key */
                                       NULL);                                     /* Public key length */
        }
    } while (retval == CMOX_ECC_ERR_WRONG_RANDOM);

    /* - Clear ECC context */
    cmox_ecc_cleanup(&ecc_ctx);

    if (retval != CMOX_ECC_SUCCESS)
    {
        return STSE_PLATFORM_ECC_GENERATE_KEY_PAIR_ERROR;
    }

    return STSE_OK;
#else
    return STSE_PLATFORM_ECC_GENERATE_KEY_PAIR_ERROR;
#endif /* STSE_CONF_ECC_NIST_P_256 || STSE_CONF_ECC_NIST_P_384 || STSE_CONF_ECC_NIST_P_521 ||\
          STSE_CONF_ECC_BRAINPOOL_P_256 || STSE_CONF_ECC_BRAINPOOL_P_384 || STSE_CONF_ECC_BRAINPOOL_P_512 ||\
          STSE_CONF_ECC_CURVE_25519 || STSE_CONF_ECC_EDWARD_25519 */
}

#if defined(STSE_CONF_USE_HOST_KEY_PROVISIONING_WRAPPED_AUTHENTICATED) || \
    defined(STSE_CONF_USE_SYMMETRIC_KEY_ESTABLISHMENT_AUTHENTICATED) ||   \
    defined(STSE_CONF_USE_SYMMETRIC_KEY_PROVISIONING_WRAPPED_AUTHENTICATED)

stse_return_code_t stse_platform_ecc_sign(
    stse_ecc_key_type_t key_type,
    PLAT_UI8 *p_priv_key,
    PLAT_UI8 *p_digest,
    PLAT_UI16 digest_len,
    PLAT_UI8 *p_signature)
{
#if defined(STSE_CONF_ECC_NIST_P_256) || defined(STSE_CONF_ECC_NIST_P_384) || defined(STSE_CONF_ECC_NIST_P_521) ||                \
    defined(STSE_CONF_ECC_BRAINPOOL_P_256) || defined(STSE_CONF_ECC_BRAINPOOL_P_384) || defined(STSE_CONF_ECC_BRAINPOOL_P_512) || \
    defined(STSE_CONF_ECC_CURVE_25519) || defined(STSE_CONF_ECC_EDWARD_25519)
    cmox_ecc_retval_t retval;
    size_t privKeyLen;
    size_t sigLen;
    cmox_ecc_impl_t curve;
    PLAT_UI8 random_number[STSE_ECC_RANDOM_BUFFER_MAX];

    curve = stse_platform_get_cmox_ecc_impl(key_type);
    privKeyLen = stse_platform_get_cmox_ecc_priv_key_len(key_type);
    sigLen = stse_platform_get_cmox_ecc_sig_len(key_type);

    if ((p_priv_key == NULL) || (p_digest == NULL) || (p_signature == NULL) ||
        (key_type >= STSE_ECC_KT_INVALID) || (digest_len == 0u) ||
        (curve == NULL) || (privKeyLen == 0u) || (sigLen == 0u))
    {
        return STSE_PLATFORM_INVALID_PARAMETER;
    }

    /*- Set ECC context */
    cmox_ecc_construct(&ecc_ctx,                     /* ECC context */
                       CMOX_MATH_FUNCS_SMALL,        /* Small math functions */
                       (PLAT_UI8 *)cmox_math_buffer, /* Crypto math buffer */
                       CMOX_MATH_BUFFER_SIZE);       /* buffer size */

#ifdef STSE_CONF_ECC_EDWARD_25519
    if (key_type == STSE_ECC_KT_ED25519)
    {
        /* - Perform EDDSA sign */
        retval = cmox_eddsa_sign(&ecc_ctx,    /* ECC context */
                                 curve,       /* Curve param */
                                 p_priv_key,  /* Private key */
                                 privKeyLen,  /* Private key length*/
                                 p_digest,    /* Message */
                                 digest_len,  /* Message length */
                                 p_signature, /* Signature */
                                 NULL);       /* Signature length */
    }
    else
#endif /* STSE_CONF_ECC_EDWARD_25519 */
    {
        do
        {
            /* - Generate a random number */
            size_t random_len = privKeyLen;
            random_len += (4u - (random_len & 0x3u)) & 0x3u;
            if ((random_len == 0u) || (random_len > sizeof(random_number)))
            {
                retval = CMOX_ECC_ERR_BAD_PARAMETERS;
                break;
            }
            stse_platform_fill_random_bytes(random_number, random_len);

            /* - Perform ECDSA sign */
            retval = cmox_ecdsa_sign(&ecc_ctx, /* ECC context */
                                     curve,    /* Curve param */
                                     random_number,
                                     random_len,
                                     p_priv_key,  /* Private key */
                                     privKeyLen,  /* Private key length*/
                                     p_digest,    /* Message */
                                     digest_len,  /* Message length */
                                     p_signature, /* Signature */
                                     NULL);       /* Signature length */
        } while (retval == CMOX_ECC_ERR_WRONG_RANDOM);
    }

    /* - Clear ECC context */
    cmox_ecc_cleanup(&ecc_ctx);

    if (retval != CMOX_ECC_SUCCESS)
    {
        return STSE_PLATFORM_ECC_SIGN_ERROR;
    }

    return STSE_OK;
#else
    return STSE_PLATFORM_ECC_SIGN_ERROR;
#endif /* STSE_CONF_ECC_NIST_P_256 || STSE_CONF_ECC_NIST_P_384 || STSE_CONF_ECC_NIST_P_521 ||\
          STSE_CONF_ECC_BRAINPOOL_P_256 || STSE_CONF_ECC_BRAINPOOL_P_384 || STSE_CONF_ECC_BRAINPOOL_P_512 ||\
          STSE_CONF_ECC_CURVE_25519 || STSE_CONF_ECC_EDWARD_25519 */
}
#endif /* STSE_CONF_USE_HOST_KEY_PROVISIONING_WRAPPED_AUTHENTICATED || STSE_CONF_USE_SYMMETRIC_KEY_ESTABLISHMENT_AUTHENTICATED ||
			STSE_CONF_USE_SYMMETRIC_KEY_PROVISIONING_WRAPPED_AUTHENTICATED */

#if defined(STSE_CONF_USE_HOST_KEY_ESTABLISHMENT) ||                      \
    defined(STSE_CONF_USE_HOST_KEY_PROVISIONING_WRAPPED) ||               \
    defined(STSE_CONF_USE_HOST_KEY_PROVISIONING_WRAPPED_AUTHENTICATED) || \
    defined(STSE_CONF_USE_SYMMETRIC_KEY_ESTABLISHMENT) ||                 \
    defined(STSE_CONF_USE_SYMMETRIC_KEY_ESTABLISHMENT_AUTHENTICATED) ||   \
    defined(STSE_CONF_USE_SYMMETRIC_KEY_PROVISIONING_WRAPPED) ||          \
    defined(STSE_CONF_USE_SYMMETRIC_KEY_PROVISIONING_WRAPPED_AUTHENTICATED)

stse_return_code_t stse_platform_ecc_ecdh(
    stse_ecc_key_type_t key_type,
    const PLAT_UI8 *p_pub_key,
    const PLAT_UI8 *p_priv_key,
    PLAT_UI8 *pSharedSecret)
{
    cmox_ecc_retval_t retval;
    size_t pubKeyLen;
    size_t privKeyLen;
    cmox_ecc_impl_t curve;

    curve = stse_platform_get_cmox_ecc_impl(key_type);
    pubKeyLen = stse_platform_get_cmox_ecc_pub_key_len(key_type);
    privKeyLen = stse_platform_get_cmox_ecc_priv_key_len(key_type);

    if ((p_pub_key == NULL) || (p_priv_key == NULL) || (pSharedSecret == NULL) ||
        (key_type >= STSE_ECC_KT_INVALID) ||
        (curve == NULL) || (pubKeyLen == 0u) || (privKeyLen == 0u))
    {
        return STSE_PLATFORM_INVALID_PARAMETER;
    }

    /*- Set ECC context */
    cmox_ecc_construct(&ecc_ctx,                     /* ECC context */
                       CMOX_MATH_FUNCS_SMALL,        /* Small math functions */
                       (PLAT_UI8 *)cmox_math_buffer, /* Crypto math buffer */
                       CMOX_MATH_BUFFER_SIZE);       /* buffer size */

    retval = cmox_ecdh(&ecc_ctx,      /* ECC context */
                       curve,         /* Curve param */
                       p_priv_key,    /* Private key (local) */
                       privKeyLen,    /* Private key length*/
                       p_pub_key,     /* Public key (remote) */
                       pubKeyLen,     /* Public key length */
                       pSharedSecret, /* Shared secret */
                       NULL);         /* Shared secret length */

    /* - Clear ECC context */
    cmox_ecc_cleanup(&ecc_ctx);

    if (retval != CMOX_ECC_SUCCESS)
    {
        return STSE_PLATFORM_ECC_ECDH_ERROR;
    }

    return STSE_OK;
}
#endif /* STSE_CONF_USE_HOST_KEY_ESTABLISHMENT) || STSE_CONF_USE_HOST_KEY_PROVISIONING_WRAPPED) ||
			STSE_CONF_USE_HOST_KEY_PROVISIONING_WRAPPED_AUTHENTICATED || STSE_CONF_USE_SYMMETRIC_KEY_ESTABLISHMENT) ||
			STSE_CONF_USE_SYMMETRIC_KEY_ESTABLISHMENT_AUTHENTICATED || STSE_CONF_USE_SYMMETRIC_KEY_PROVISIONING_WRAPPED ||
			STSE_CONF_USE_SYMMETRIC_KEY_PROVISIONING_WRAPPED_AUTHENTICATED */

#if defined(STSE_CONF_USE_HOST_KEY_PROVISIONING_WRAPPED) ||               \
    defined(STSE_CONF_USE_HOST_KEY_PROVISIONING_WRAPPED_AUTHENTICATED) || \
    defined(STSE_CONF_USE_SYMMETRIC_KEY_PROVISIONING_WRAPPED) ||          \
    defined(STSE_CONF_USE_SYMMETRIC_KEY_PROVISIONING_WRAPPED_AUTHENTICATED)

#define KEK_WRAP_IV_SIZE 8
const PLAT_UI8 KEK_WRAP_IV[KEK_WRAP_IV_SIZE] = {0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6};

stse_return_code_t stse_platform_nist_kw_encrypt(PLAT_UI8 *p_payload, PLAT_UI32 payload_length,
                                                PLAT_UI8 *p_key, PLAT_UI8 key_length,
                                                PLAT_UI8 *p_output, PLAT_UI32 *p_output_length)
{
    cmox_cipher_retval_t retval;
    size_t cmox_output_length = *p_output_length;

    retval = cmox_cipher_encrypt(
        CMOX_AESSMALL_KEYWRAP_ENC_ALGO,
        p_payload, payload_length,
        p_key, key_length,
        KEK_WRAP_IV, KEK_WRAP_IV_SIZE,
        p_output, &cmox_output_length);

    if (retval != CMOX_CIPHER_SUCCESS)
    {
        return STSE_PLATFORM_KEYWRAP_ERROR;
    }

    *p_output_length = (PLAT_UI32)cmox_output_length;

    return STSE_OK;
}
#endif /* STSE_CONF_USE_HOST_KEY_PROVISIONING_WRAPPED || STSE_CONF_USE_HOST_KEY_PROVISIONING_WRAPPED_AUTHENTICATED ||
			STSE_CONF_USE_SYMMETRIC_KEY_PROVISIONING_WRAPPED || STSE_CONF_USE_SYMMETRIC_KEY_PROVISIONING_WRAPPED_AUTHENTICATED */
