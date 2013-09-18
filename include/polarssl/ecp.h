/**
 * \file ecp.h
 *
 * \brief Elliptic curves over GF(p)
 *
 *  Copyright (C) 2006-2013, Brainspark B.V.
 *
 *  This file is part of PolarSSL (http://www.polarssl.org)
 *  Lead Maintainer: Paul Bakker <polarssl_maintainer at polarssl.org>
 *
 *  All rights reserved.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
#ifndef POLARSSL_ECP_H
#define POLARSSL_ECP_H

#include "polarssl/bignum.h"

/*
 * ECP error codes
 */
#define POLARSSL_ERR_ECP_BAD_INPUT_DATA                    -0x4F80  /**< Bad input parameters to function. */
#define POLARSSL_ERR_ECP_BUFFER_TOO_SMALL                  -0x4F00  /**< The buffer is too small to write to. */
#define POLARSSL_ERR_ECP_FEATURE_UNAVAILABLE               -0x4E80  /**< Requested curve not available. */
#define POLARSSL_ERR_ECP_VERIFY_FAILED                     -0x4E00  /**< The signature is not valid. */
#define POLARSSL_ERR_ECP_MALLOC_FAILED                     -0x4D80  /**< Memory allocation failed. */
#define POLARSSL_ERR_ECP_RANDOM_FAILED                     -0x4D00  /**< Generation of random value, such as (ephemeral) key, failed. */
#define POLARSSL_ERR_ECP_INVALID_KEY                       -0x4C80  /**< Invalid private or public key. */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Domain parameters (curve, subgroup and generator) identifiers.
 *
 * Only curves over prime fields are supported.
 *
 * \warning This library does not support validation of arbitrary domain
 * parameters. Therefore, only well-known domain parameters from trusted
 * sources should be used. See ecp_use_known_dp().
 */
typedef enum
{
    POLARSSL_ECP_DP_NONE = 0,
    POLARSSL_ECP_DP_SECP192R1,      /*!< 192-bits NIST curve  */
    POLARSSL_ECP_DP_SECP224R1,      /*!< 224-bits NIST curve  */
    POLARSSL_ECP_DP_SECP256R1,      /*!< 256-bits NIST curve  */
    POLARSSL_ECP_DP_SECP384R1,      /*!< 384-bits NIST curve  */
    POLARSSL_ECP_DP_SECP521R1,      /*!< 521-bits NIST curve  */
} ecp_group_id;

/**
 * Curve information for use by other modules
 */
typedef struct
{
    ecp_group_id grp_id;    /*!< Internal identifier        */
    uint16_t tls_id;        /*!< TLS NamedCurve identifier  */
    uint16_t size;          /*!< Curve size in bits         */
    const char *name;       /*!< Human-friendly name        */
} ecp_curve_info;

/**
 * \brief           ECP point structure (jacobian coordinates)
 *
 * \note            All functions expect and return points satisfying
 *                  the following condition: Z == 0 or Z == 1. (Other
 *                  values of Z are used by internal functions only.)
 *                  The point is zero, or "at infinity", if Z == 0.
 *                  Otherwise, X and Y are its standard (affine) coordinates.
 */
typedef struct
{
    mpi X;          /*!<  the point's X coordinate  */
    mpi Y;          /*!<  the point's Y coordinate  */
    mpi Z;          /*!<  the point's Z coordinate  */
}
ecp_point;

/**
 * \brief           ECP group structure
 *
 * The curves we consider are defined by y^2 = x^3 + A x + B mod P,
 * and a generator for a large subgroup of order N is fixed.
 *
 * pbits and nbits must be the size of P and N in bits.
 *
 * If modp is NULL, reduction modulo P is done using a generic algorithm.
 * Otherwise, it must point to a function that takes an mpi in the range
 * 0..2^(2*pbits)-1 and transforms it in-place in an integer of little more
 * than pbits, so that the integer may be efficiently brought in the 0..P-1
 * range by a few additions or substractions. It must return 0 on success and
 * non-zero on failure.
 */
typedef struct
{
    ecp_group_id id;    /*!<  RFC 4492 group ID                 */
    mpi P;              /*!<  prime modulus of the base field   */
    mpi A;              /*!<  currently unused (-3 assumed)     */
    mpi B;              /*!<  constant term in the equation     */
    ecp_point G;        /*!<  generator of the subgroup used    */
    mpi N;              /*!<  the order of G                    */
    size_t pbits;       /*!<  number of bits in P               */
    size_t nbits;       /*!<  number of bits in N               */
    unsigned int h;     /*!<  cofactor (unused now: assume 1)   */
    int (*modp)(mpi *); /*!<  function for fast reduction mod P */
    int (*t_pre)(ecp_point *, void *);  /*!< currently unused   */
    int (*t_post)(ecp_point *, void *); /*!< currently unused   */
    void *t_data;                       /*!< currently unused   */
    ecp_point *T;       /*!<  pre-computed points (unused now)  */
    size_t T_size;      /*!<  number for pre-computed points    */
}
ecp_group;

/**
 * \brief           ECP key pair structure
 *
 * A generic key pair that could be used for ECDSA, fixed ECDH, etc.
 *
 * \note Members purposefully in the same order as struc ecdsa_context.
 */
typedef struct
{
    ecp_group grp;      /*!<  Elliptic curve and base point     */
    mpi d;              /*!<  our secret value                  */
    ecp_point Q;        /*!<  our public value                  */
}
ecp_keypair;

/**
 * Maximum size of the groups (that is, of N and P)
 */
#define POLARSSL_ECP_MAX_BITS     521
#define POLARSSL_ECP_MAX_BYTES    ( ( POLARSSL_ECP_MAX_BITS + 7 ) / 8 )
#define POLARSSL_ECP_MAX_PT_LEN   ( 2 * POLARSSL_ECP_MAX_BYTES + 1 )

/*
 * Maximum window size (actually, NAF width) used for point multipliation.
 * Default: 8.
 * Minimum value: 2. Maximum value: 8.
 *
 * Result is an array of at most ( 1 << ( POLARSSL_ECP_WINDOW_SIZE - 1 ) )
 * points used for point multiplication.
 *
 * Reduction in size may reduce speed for big curves.
 */
#define POLARSSL_ECP_WINDOW_SIZE    8   /**< Maximum NAF width used. */

/*
 * Point formats, from RFC 4492's enum ECPointFormat
 */
#define POLARSSL_ECP_PF_UNCOMPRESSED    0   /**< Uncompressed point format */
#define POLARSSL_ECP_PF_COMPRESSED      1   /**< Compressed point format */

/*
 * Some other constants from RFC 4492
 */
#define POLARSSL_ECP_TLS_NAMED_CURVE    3   /**< ECCurveType's named_curve */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief           Return the list of supported curves with associated info
 *
 * \return          A statically allocated array, the last entry is 0.
 */
const ecp_curve_info *ecp_curve_list( void );

/**
 * \brief           Initialize a point (as zero)
 */
void ecp_point_init( ecp_point *pt );

/**
 * \brief           Initialize a group (to something meaningless)
 */
void ecp_group_init( ecp_group *grp );

/**
 * \brief           Initialize a key pair (as an invalid one)
 */
void ecp_keypair_init( ecp_keypair *key );

/**
 * \brief           Free the components of a point
 */
void ecp_point_free( ecp_point *pt );

/**
 * \brief           Free the components of an ECP group
 */
void ecp_group_free( ecp_group *grp );

/**
 * \brief           Free the components of a key pair
 */
void ecp_keypair_free( ecp_keypair *key );

/**
 * \brief           Set a point to zero
 *
 * \param pt        Destination point
 *
 * \return          0 if successful,
 *                  POLARSSL_ERR_MPI_MALLOC_FAILED if memory allocation failed
 */
int ecp_set_zero( ecp_point *pt );

/**
 * \brief           Tell if a point is zero
 *
 * \param pt        Point to test
 *
 * \return          1 if point is zero, 0 otherwise
 */
int ecp_is_zero( ecp_point *pt );

/**
 * \brief           Copy the contents of point Q into P
 *
 * \param P         Destination point
 * \param Q         Source point
 *
 * \return          0 if successful,
 *                  POLARSSL_ERR_MPI_MALLOC_FAILED if memory allocation failed
 */
int ecp_copy( ecp_point *P, const ecp_point *Q );

/**
 * \brief           Copy the contents of a group object
 *
 * \param dst       Destination group
 * \param src       Source group
 *
 * \return          0 if successful,
 *                  POLARSSL_ERR_MPI_MALLOC_FAILED if memory allocation failed
 */
int ecp_group_copy( ecp_group *dst, const ecp_group *src );

/**
 * \brief           Import a non-zero point from two ASCII strings
 *
 * \param P         Destination point
 * \param radix     Input numeric base
 * \param x         First affine coordinate as a null-terminated string
 * \param y         Second affine coordinate as a null-terminated string
 *
 * \return          0 if successful, or a POLARSSL_ERR_MPI_XXX error code
 */
int ecp_point_read_string( ecp_point *P, int radix,
                           const char *x, const char *y );

/**
 * \brief           Import an ECP group from null-terminated ASCII strings
 *
 * \param grp       Destination group
 * \param radix     Input numeric base
 * \param p         Prime modulus of the base field
 * \param b         Constant term in the equation
 * \param gx        The generator's X coordinate
 * \param gy        The generator's Y coordinate
 * \param n         The generator's order
 *
 * \return          0 if successful, or a POLARSSL_ERR_MPI_XXX error code
 *
 * \note            Sets all fields except modp.
 */
int ecp_group_read_string( ecp_group *grp, int radix,
                           const char *p, const char *b,
                           const char *gx, const char *gy, const char *n);

/**
 * \brief           Export a point into unsigned binary data
 *
 * \param grp       Group to which the point should belong
 * \param P         Point to export
 * \param format    Point format, should be a POLARSSL_ECP_PF_XXX macro
 * \param olen      Length of the actual output
 * \param buf       Output buffer
 * \param buflen    Length of the output buffer
 *
 * \return          0 if successful,
 *                  or POLARSSL_ERR_ECP_BAD_INPUT_DATA
 *                  or POLARSSL_ERR_ECP_BUFFER_TOO_SMALL
 */
int ecp_point_write_binary( const ecp_group *grp, const ecp_point *P,
                            int format, size_t *olen,
                            unsigned char *buf, size_t buflen );

/**
 * \brief           Import a point from unsigned binary data
 *
 * \param grp       Group to which the point should belong
 * \param P         Point to import
 * \param buf       Input buffer
 * \param ilen      Actual length of input
 *
 * \return          0 if successful,
 *                  POLARSSL_ERR_ECP_BAD_INPUT_DATA if input is invalid
 *                  POLARSSL_ERR_MPI_MALLOC_FAILED if memory allocation failed
 *
 * \note            This function does NOT check that the point actually
 *                  belongs to the given group, see ecp_check_pubkey() for
 *                  that.
 */
int ecp_point_read_binary( const ecp_group *grp, ecp_point *P,
                           const unsigned char *buf, size_t ilen );

/**
 * \brief           Set a group using well-known domain parameters
 *
 * \param grp       Destination group
 * \param index     Index in the list of well-known domain parameters
 *
 * \return          O if successful,
 *                  POLARSSL_ERR_MPI_XXX if initialization failed
 *                  POLARSSL_ERR_ECP_FEATURE_UNAVAILABLE for unkownn groups
 *
 * \note            Index should be a value of RFC 4492's enum NamdeCurve,
 *                  possibly in the form of a POLARSSL_ECP_DP_XXX macro.
 */
int ecp_use_known_dp( ecp_group *grp, ecp_group_id index );

/**
 * \brief           Set a group from a TLS ECParameters record
 *
 * \param grp       Destination group
 * \param buf       &(Start of input buffer)
 * \param len       Buffer length
 *
 * \return          O if successful,
 *                  POLARSSL_ERR_MPI_XXX if initialization failed
 *                  POLARSSL_ERR_ECP_BAD_INPUT_DATA if input is invalid
 */
int ecp_tls_read_group( ecp_group *grp, const unsigned char **buf, size_t len );

/**
 * \brief           Write the TLS ECParameters record for a group
 *
 * \param grp       ECP group used
 * \param olen      Number of bytes actually written
 * \param buf       Buffer to write to
 * \param blen      Buffer length
 *
 * \return          0 if successful,
 *                  or POLARSSL_ERR_ECP_BUFFER_TOO_SMALL
 */
int ecp_tls_write_group( const ecp_group *grp, size_t *olen,
                         unsigned char *buf, size_t blen );

/**
 * \brief           Get a TLS NamedCurve value from an internal group identifier
 *
 * \param grp_id    A POLARSSL_ECP_DP_XXX value
 *
 * \return          The associated TLS NamedCurve value on success,
 *                  0 on failure.
 */
uint16_t ecp_named_curve_from_grp_id( ecp_group_id id );

/**
 * \brief           Get an internal group identifier from a TLS NamedCurve value
 *
 * \param curve     A value from TLS's enum NamedCurve
 *
 * \return          The associated POLARSSL_ECP_DP_XXX identifer on success,
 *                  POLARSSL_ECP_DP_NONE on failure.
 */
ecp_group_id ecp_grp_id_from_named_curve( uint16_t curve );

/**
 * \brief           Import a point from a TLS ECPoint record
 *
 * \param grp       ECP group used
 * \param pt        Destination point
 * \param buf       $(Start of input buffer)
 * \param len       Buffer length
 *
 * \return          O if successful,
 *                  POLARSSL_ERR_MPI_XXX if initialization failed
 *                  POLARSSL_ERR_ECP_BAD_INPUT_DATA if input is invalid
 */
int ecp_tls_read_point( const ecp_group *grp, ecp_point *pt,
                        const unsigned char **buf, size_t len );

/**
 * \brief           Export a point as a TLS ECPoint record
 *
 * \param grp       ECP group used
 * \param pt        Point to export
 * \param format    Export format
 * \param olen      length of data written
 * \param buf       Buffer to write to
 * \param blen      Buffer length
 *
 * \return          0 if successful,
 *                  or POLARSSL_ERR_ECP_BAD_INPUT_DATA
 *                  or POLARSSL_ERR_ECP_BUFFER_TOO_SMALL
 */
int ecp_tls_write_point( const ecp_group *grp, const ecp_point *pt,
                         int format, size_t *olen,
                         unsigned char *buf, size_t blen );

/**
 * \brief           Addition: R = P + Q
 *
 * \param grp       ECP group
 * \param R         Destination point
 * \param P         Left-hand point
 * \param Q         Right-hand point
 *
 * \return          0 if successful,
 *                  POLARSSL_ERR_MPI_MALLOC_FAILED if memory allocation failed
 */
int ecp_add( const ecp_group *grp, ecp_point *R,
             const ecp_point *P, const ecp_point *Q );

/**
 * \brief           Subtraction: R = P - Q
 *
 * \param grp       ECP group
 * \param R         Destination point
 * \param P         Left-hand point
 * \param Q         Right-hand point
 *
 * \return          0 if successful,
 *                  POLARSSL_ERR_MPI_MALLOC_FAILED if memory allocation failed
 */
int ecp_sub( const ecp_group *grp, ecp_point *R,
             const ecp_point *P, const ecp_point *Q );

/**
 * \brief           Multiplication by an integer: R = m * P
 *
 * \param grp       ECP group
 * \param R         Destination point
 * \param m         Integer by which to multiply
 * \param P         Point to multiply
 * \param f_rng     RNG function (see notes)
 * \param p_rng     RNG parameter
 *
 * \return          0 if successful,
 *                  POLARSSL_ERR_MPI_MALLOC_FAILED if memory allocation failed
 *                  POLARSSL_ERR_ECP_BAD_INPUT_DATA if m < 0 of m has greater
 *                  bit length than N, the number of points in the group.
 *
 * \note            In order to prevent simple timing attacks, this function
 *                  executes a constant number of operations (that is, point
 *                  doubling and addition of distinct points) for random m in
 *                  the allowed range.
 *
 * \note            If f_rng is not NULL, it is used to randomize projective
 *                  coordinates of indermediate results, in order to prevent
 *                  more elaborate timing attacks relying on intermediate
 *                  operations. (This is a prophylactic measure since no such
 *                  attack has been published yet.) Since this contermeasure
 *                  has very low overhead, it is recommended to always provide
 *                  a non-NULL f_rng parameter when using secret inputs.
 */
int ecp_mul( ecp_group *grp, ecp_point *R,
             const mpi *m, const ecp_point *P,
             int (*f_rng)(void *, unsigned char *, size_t), void *p_rng );


/**
 * \brief           Check that a point is a valid public key on this curve
 *
 * \param grp       Curve/group the point should belong to
 * \param pt        Point to check
 *
 * \return          0 if point is a valid public key,
 *                  POLARSSL_ERR_ECP_INVALID_KEY otherwise.
 *
 * \note            This function only checks the point is non-zero, has valid
 *                  coordinates and lies on the curve, but not that it is
 *                  indeed a multiple of G. This is additional check is more
 *                  expensive, isn't required by standards, and shouldn't be
 *                  necessary if the group used has a small cofactor. In
 *                  particular, it is useless for the NIST groups which all
 *                  have a cofactor of 1.
 *
 * \note            Uses bare components rather than an ecp_keypair structure
 *                  in order to ease use with other structures such as
 *                  ecdh_context of ecdsa_context.
 */
int ecp_check_pubkey( const ecp_group *grp, const ecp_point *pt );

/**
 * \brief           Check that an mpi is a valid private key for this curve
 *
 * \param grp       Group used
 * \param d         Integer to check
 *
 * \return          0 if point is a valid private key,
 *                  POLARSSL_ERR_ECP_INVALID_KEY otherwise.
 *
 * \note            Uses bare components rather than an ecp_keypair structure
 *                  in order to ease use with other structures such as
 *                  ecdh_context of ecdsa_context.
 */
int ecp_check_privkey( const ecp_group *grp, const mpi *d );

/**
 * \brief           Generate a keypair
 *
 * \param grp       ECP group
 * \param d         Destination MPI (secret part)
 * \param Q         Destination point (public part)
 * \param f_rng     RNG function
 * \param p_rng     RNG parameter
 *
 * \return          0 if successful,
 *                  or a POLARSSL_ERR_ECP_XXX or POLARSSL_MPI_XXX error code
 *
 * \note            Uses bare components rather than an ecp_keypair structure
 *                  in order to ease use with other structures such as
 *                  ecdh_context of ecdsa_context.
 */
int ecp_gen_keypair( ecp_group *grp, mpi *d, ecp_point *Q,
                     int (*f_rng)(void *, unsigned char *, size_t),
                     void *p_rng );

/**
 * \brief          Checkup routine
 *
 * \return         0 if successful, or 1 if the test failed
 */
int ecp_self_test( int verbose );

#ifdef __cplusplus
}
#endif

#endif