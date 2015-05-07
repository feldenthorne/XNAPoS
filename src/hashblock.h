#ifndef HASHBLOCK_H
#define HASHBLOCK_H

#include "uint256.h"
#include "rca/sph_keccak.h"
#include "rca/sph_cubehash.h"
#include "rca/sph_panama.h"
#include "rca/sph_whirlpool.h"

#ifndef QT_NO_DEBUG
#include <string>
#endif

#ifdef GLOBALDEFINED
#define GLOBAL
#else
#define GLOBAL extern
#endif

GLOBAL sph_keccak512_context     z_keccak;
GLOBAL sph_panama_context		 z_panama;
GLOBAL sph_cubehash512_context   z_cubehash;
GLOBAL sph_whirlpool_context     z_whirlpool;

#define fillz() do { \
	sph_keccak512_init(&z_keccak); \
	sph_cubehash512_init(&z_cubehash); \
	sph_panama_init(&z_panama); \
	sph_whirlpool_init(&z_whirlpool); \
} while (0) 

#define ZKECCAK (memcpy(&ctx_keccak512, &z_keccak, sizeof(z_keccak)))
#define ZCUBEHASH (memcpy(&ctx_cubehash512, &z_cubehash, sizeof(z_cubehash)))
#define ZPANAMA (memcpy(&ctx_panama, &z_panama, sizeof(z_panama)))
#define ZWHIRLPOOL (memcpy(&ctx_whirlpool, &z_whirlpool, sizeof(z_whirlpool)))

template<typename T1>
inline uint256 Hash9(const T1 pbegin, const T1 pend)

{
    sph_keccak512_context      ctx_keccak512;
    sph_cubehash512_context    ctx_cubehash512;
    sph_panama_context         ctx_panama;
    sph_whirlpool_context      ctx_whirlpool;
    static unsigned char pblank[1];

#ifndef QT_NO_DEBUG
    //std::string strhash;
    //strhash = "";
#endif
    
    uint512 hash[5];

    sph_panama_init(&ctx_panama);
    sph_panama (&ctx_panama, (pbegin == pend ? pblank : static_cast<const void*>(&pbegin[0])), (pend - pbegin) * sizeof(pbegin[0]));
    sph_panama_close(&ctx_panama, static_cast<void*>(&hash[0]));
    
    sph_whirlpool_init(&ctx_whirlpool);
    sph_whirlpool (&ctx_whirlpool, static_cast<const void*>(&hash[0]), 64);
    sph_whirlpool_close(&ctx_whirlpool, static_cast<void*>(&hash[1]));
    
    sph_keccak512_init(&ctx_keccak512);
    sph_keccak512 (&ctx_keccak512, static_cast<const void*>(&hash[1]), 64);
    sph_keccak512_close(&ctx_keccak512, static_cast<void*>(&hash[2]));
    
    sph_panama_init(&ctx_panama);
    sph_panama (&ctx_panama, static_cast<const void*>(&hash[2]), 64);
    sph_panama_close(&ctx_panama, static_cast<void*>(&hash[3]));
    
    sph_cubehash512_init(&ctx_cubehash512);
    sph_cubehash512 (&ctx_cubehash512, static_cast<const void*>(&hash[3]), 64);
    sph_cubehash512_close(&ctx_cubehash512, static_cast<void*>(&hash[4]));

    return hash[4].trim256();
}






#endif // HASHBLOCK_H
