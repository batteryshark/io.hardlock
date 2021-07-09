//
// File: hl_seed.c
//
// HARDLOCK Key Seeds brute-force finder
//
// Copyright (C) 2002-2005, SaPu
//
// Purpose:
//	Finding the Key Seeds from the ID_Ref & ID_Verify values.
//
// Note:
//	Although the program has been optimized for speed using 'asm' code,
//	a full 'brute force' search still requires 20-30 hours on a 2GHz CPU.
//	If interrupted, the search is restarted from last savepoint.
//
// License:
//	This program is free software; you can redistribute it and/or modify
//	it under the terms of the GNU General Public License as published by
//	the Free Software Foundation; either version 2, or (at your option)
//	any later version.
//	This program is distributed in the hope that it will be useful,
//	but WITHOUT ANY WARRANTY; without even the implied warranty of
//	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//	GNU General Public License for more details.
//	You should have received a copy of the GNU General Public License
//	along with this program; if not, write to the Free Software
//	Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
//
// Disclaimer:
//	This program could be used for didactical purposes only.
//	Author is not responsible for any damage derived from this program.
//

//
//------------------------------------------------------------------------------
// External #defines (to be added on project setting):
//
// USE_ASM_CODE - use optimized 'asm' code (speed-up the search algo)
//------------------------------------------------------------------------------
//


#include <stdio.h>
#include <stdarg.h>
#include <conio.h>
#include <windows.h>
#include <assert.h>

#define	RESTART_FILE	"restart.dat"
#define	RESULT_FILE		"result.txt"

#define	NUM_WORD8BITS	12870	// number of word with 8 x '1' bits
#define	NUM_WORD4DIGS	43680	// number of word with 4 x different digits

typedef struct {
	BYTE	PtrArray[16];
	BYTE	SeedArray[4];
	BYTE	Var1,Var2;
	WORD	Seed1,Seed2,Seed3;
} HLGDATA;

typedef struct {
	BYTE	RefKey[8];
	BYTE	VerKey[8];
	WORD	crypt_out[5][2];
	BYTE	crypt_bits[5];
	int		restart_idx;
} RESTART_DATA;

WORD	crypt_out[5][2];
BYTE	crypt_bits[5];
BYTE	ref_out[5*2*16];	// half bytes out
BYTE	ref_bits[5*8];		// bits in
BOOL	seed2_msbit;		// msb bit of 'Seed2'
WORD	word8bits_list[NUM_WORD8BITS];	// list of words with 8 x '1' bits (Seed1/2 candidate)
BYTE	pairnbits_list[256][256][4];	// list of nbits '00','01','10','11' x pair [byte2][byte1]
WORD	word4digs_list[NUM_WORD4DIGS];	// list of word with 4 x different digits (Seed3 candidate)
BYTE	digs4digs_list[NUM_WORD4DIGS][4];// same as 'word4digs_list', but as 4 x big-endian digits format
HLGDATA	g;					// algo data


void find_seed(BYTE *RefKey, BYTE *VerKey);

void find_ref_key_data(BYTE *RefKey, BYTE *VerKey);
void HL_CRYPT_ONE(const BYTE *data_in, BYTE *data_out, WORD bits_in);

void build_candidate_lists();
void expand_ref_key_data();

void check_candidate_seed12(WORD seed1, WORD seed2);

BOOL load_restart_file(BYTE *RefKey, BYTE *VerKey, int *restart_idx);
void save_restart_file(BYTE *RefKey, BYTE *VerKey, int restart_idx);
void unlink_restart_file();
void write_result_file(WORD	Seed1, WORD	Seed2, WORD Seed3);


//------------------------------------------------------------------------------

void find_seed(BYTE *RefKey, BYTE *VerKey)
{
	int		restart_idx = 0;

	build_candidate_lists();
	if (!load_restart_file(RefKey, VerKey, &restart_idx))
		find_ref_key_data(RefKey, VerKey);
	expand_ref_key_data();
	int seed2_offset = (seed2_msbit == 0) ? 0 : NUM_WORD8BITS / 2;
	DWORD startTicks = GetTickCount();
	for (int i = restart_idx; i < NUM_WORD8BITS / 2; i++) {
		printf("done %d of %d", i, NUM_WORD8BITS / 2);
		if (i != restart_idx) {
			DWORD elapsed = (GetTickCount() - startTicks) / 1000;
			DWORD remaining = elapsed * ((NUM_WORD8BITS / 2) - i) / (i - restart_idx);
			printf(" (elapsed: %dh%dm%ds, remaining: %dh%dm%ds)          \r",
				elapsed / 3600, (elapsed / 60) % 60, elapsed % 60,
				remaining / 3600, (remaining / 60) % 60, remaining % 60);
		}
		printf("\r"); fflush(stdout);
		save_restart_file(RefKey, VerKey, i);
		WORD word2 = word8bits_list[i + seed2_offset];
		for (int j = 0; j < NUM_WORD8BITS; j++) {
			WORD word1 = word8bits_list[j];
			BYTE *pairnbits[2] = { pairnbits_list[LOBYTE(word2)][LOBYTE(word1)], pairnbits_list[HIBYTE(word2)][HIBYTE(word1)] };
			if ((pairnbits[0][0] + pairnbits[1][0]) != 4 ||
				(pairnbits[0][1] + pairnbits[1][1]) != 4 ||
				(pairnbits[0][2] + pairnbits[1][2]) != 4 ||
				(pairnbits[0][3] + pairnbits[1][3]) != 4)
				continue;
			check_candidate_seed12(word1, word2);
		}
	}
	unlink_restart_file();
}

//------------------------------------------------------------------------------

void find_ref_key_data(BYTE *RefKey, BYTE *VerKey)
{
	WORD	b0, bits[5];
	BYTE	out[6][8];
	int		i, nfound = 0;

	memcpy(out[0], RefKey, 8);
	for (b0 = 0x00; b0 <= 0x01; b0++) {
		for (bits[0] = b0; bits[0] <= 0xFF; bits[0] += 2) {
			HL_CRYPT_ONE(out[0], out[1], bits[0]);
			for (bits[1] = b0; bits[1] <= 0xFF; bits[1] += 2) {
				HL_CRYPT_ONE(out[1], out[2], bits[1]);
				for (bits[2] = b0; bits[2] <= 0xFF; bits[2] += 2) {
					HL_CRYPT_ONE(out[2], out[3], bits[2]);
					for (bits[3] = b0; bits[3] <= 0xFF; bits[3] += 2) {
						HL_CRYPT_ONE(out[3], out[4], bits[3]);
						if (*(DWORD *)&out[4][4] != *(DWORD *)&VerKey[4])
							continue;
						for (bits[4] = b0; bits[4] <= 0xFF; bits[4] += 2) {
							HL_CRYPT_ONE(out[4], out[5], bits[4]);
							if (*(DWORD *)&out[5][0] != *(DWORD *)&VerKey[4] ||
								*(DWORD *)&out[5][4] != *(DWORD *)&VerKey[0])
								continue;
							nfound++;
							for (i = 0; i < 5; i++) {
								crypt_out[i][0] = *(WORD *)&out[i][4];
								crypt_out[i][1] = *(WORD *)&out[i][6];
								crypt_bits[i] = bits[i] ^ 0xFF;
							}
							printf("Reference data found:\n");
							for (i = 0; i < 5; i++) {
								printf(" %04x %04x -> %02x\n", crypt_out[i][0], crypt_out[i][1], crypt_bits[i]);
							}
						} // end for (bits[4])
					} // end for (bits[0..3])
				}
			}
		}
	}
	assert(nfound == 1);
}

static __inline BYTE ROL8(BYTE a, int nbits) { return (a << nbits) | (a >> (8-nbits)); }
static __inline WORD ROL16(WORD a, int nbits) { return (a << nbits) | (a >> (16-nbits)); }
static __inline WORD CipherFunction2(WORD Word3, WORD Word4, WORD bits_in) {
	WORD	tmpret = (bits_in << 8);
	tmpret = ROL16(Word4 ^ tmpret, 1);
	return MAKEWORD(LOBYTE(tmpret) + HIBYTE(tmpret), HIBYTE(tmpret));
}

void HL_CRYPT_ONE(const BYTE *data_in, BYTE *data_out, WORD bits_in)
{
#ifndef	USE_ASM_CODE
	WORD Word1 = *(WORD *)&data_in[0];
	WORD Word2 = *(WORD *)&data_in[2];
	WORD Word3 = *(WORD *)&data_in[4];
	WORD Word4 = *(WORD *)&data_in[6];
	WORD transf = CipherFunction2(Word3, Word4, bits_in);
	transf ^= Word3 ^ Word4;
	BYTE tmp1 = ROL8(ROL8(LOBYTE(transf) + HIBYTE(transf), 1) + 1, 1);
	BYTE tmp2 = ROL8(tmp1 + LOBYTE(transf), 2);
	transf = MAKEWORD(tmp2, tmp1);
	WORD temp = transf + Word4;
	temp = ROL16(MAKEWORD(LOBYTE(temp)+1, HIBYTE(temp)), 2);
	transf ^= Word1;
	temp ^= Word2;
	Word1 = Word3;
	Word2 = Word4;
	Word3 ^= transf;
	Word4 ^= temp;
	*(WORD *)&data_out[0] = Word1;
	*(WORD *)&data_out[2] = Word2;
	*(WORD *)&data_out[4] = Word3;
	*(WORD *)&data_out[6] = Word4;
#else //USE_ASM_CODE
	__asm mov	esi,[data_in]
	__asm mov	edi,[data_out]
	__asm mov	bx,[esi+4]	// bx = Word3
	__asm mov	dx,[esi+6]	// dx = Word4
	__asm mov	ax,[bits_in]// ax = bits_in
	__asm shl	ax,8
	__asm xor	eax,edx
	__asm rol	ax,1
	__asm add	al,ah		// ax = transf
	__asm xor	eax,edx
	__asm xor	eax,ebx
	__asm add	ah,al
	__asm rol	ah,1
	__asm inc	ah
	__asm rol	ah,1		// ah = tmp1
	__asm add	al,ah
	__asm rol	al,2		// al = tmp2, ax = transf
	__asm mov	cx,dx
	__asm add	cx,ax
	__asm inc	cl
	__asm rol	cx,2		// cx = temp
	__asm xor	ax,[esi+0]
	__asm xor	cx,[esi+2]
	__asm mov	[edi+0],bx
	__asm mov	[edi+2],dx
	__asm xor	bx,ax
	__asm xor	dx,cx
	__asm mov	[edi+4],bx
	__asm mov	[edi+6],dx
#endif//USE_ASM_CODE
}

//------------------------------------------------------------------------------

void build_candidate_lists()
{
	int		i, j, k, cnt;

	for (i = 0, cnt = 0; i <= 0xFFFF; i++) {
		int nbits = 0;
		for (j = 0x0001; j <= 0x8000; j <<= 1) {
			if (i & j)
				nbits++;
		}
		if (nbits != 8)
			continue;
		word8bits_list[cnt++] = (WORD)i;
	}
	assert(cnt == NUM_WORD8BITS);

	for (i = 0, cnt = 0; i <= 0xFFFF; i++) {
		BYTE	digs[4] = { (i >> 12) & 0x0F, (i >> 8) & 0x0F, (i >> 4) & 0x0F, i & 0x0F };
		if (digs[0] == digs[1] || digs[0] == digs[2] || digs[0] == digs[3] ||
			digs[1] == digs[2] || digs[1] == digs[3] || digs[2] == digs[3])
			continue;
		word4digs_list[cnt] = i;
		*(DWORD *)digs4digs_list[cnt++] = *(DWORD *)digs;
	}
	assert(cnt == NUM_WORD4DIGS);

	memset(pairnbits_list, 0, sizeof(pairnbits_list));
	for (i = 0; i < 256; i++) {
		for (j = 0; j < 256; j++) {
			for (k = 0; k < 8; k++) {
				pairnbits_list[i][j][(((i >> k) & 1) << 1) | ((j >> k) & 1)]++;
			}
		}
	}
}

void expand_ref_key_data()
{
	int		i, j, k;

	for (i = 0; i < 5; i++) {
		for (j = 0; j < 2; j++) {
			for (k = 0; k < 16; k++) {
				ref_out[(i*2+j)*16+k] = (ROL16(crypt_out[i][j], k) >> 2) & 0x0F;
			}
		}
		for (j = 0; j < 8; j++) {
			ref_bits[i*8+j] = (crypt_bits[i] >> j) & 0x01;
		}
	}
	seed2_msbit = ref_bits[0];
}

//------------------------------------------------------------------------------
void check_candidate_seed12(WORD seed1, WORD seed2)
{
#ifndef	USE_ASM_CODE
	int idx, i, j, k;

	g.Seed1 = seed1;
	g.Seed2 = seed2;
	for (i = 0; i < 16; i++) {
		g.PtrArray[i] = (((g.Seed1 >> i) & 1) << 1) | ((g.Seed2 >> i) & 1);
	}
	for (int idx = 0; idx < NUM_WORD4DIGS; idx++) {
		g.Seed3 = word4digs_list[idx];
		*(DWORD *)g.SeedArray = *(DWORD *)digs4digs_list[idx];
		//g.SeedArray[0] = (g.Seed3 >> 12) & 0x0F;
		//g.SeedArray[1] = (g.Seed3 >> 8) & 0x0F;
		//g.SeedArray[2] = (g.Seed3 >> 4) & 0x0F;
		//g.SeedArray[3] = g.Seed3 & 0xF;
		const BYTE *pout = &ref_out[0];
		const BYTE *pbits = &ref_bits[0];
		for (i = 0; i < 5; i++) {
			g.Var1 = 0x0F;
			g.Var2 = 0;
			for (j = 0; j < (2*4); j++) {
				for (k = 0; k < 4; k++) {
					// g.Var1 = index x bit from Seed1 & Seed2
					BYTE tmpPtr = g.PtrArray[g.Var1];	// bit1 = seed1, bit0 = seed2
					if (k == 0 && (tmpPtr & 1) != *pbits++) {
						goto next_value;
					}
					g.Var1 ^= *pout++ ^ g.Var2 ^ g.SeedArray[tmpPtr];
					// g.Var2 = shift register x xor with g.Var1
					g.Var2 = ((g.Var2 << 1) | (tmpPtr >> 1)) & 0x0F;
				}
			}
		}
next_value:
		if (i == 5) {
			write_result_file(g.Seed1, g.Seed2, g.Seed3);
		}
	}
#else //USE_ASM_CODE
	int		i, j;

	// init g.Seed12 & g.PtrArray
	__asm mov	bx,[seed1]
	__asm mov	dx,[seed2]
	__asm mov	[g.Seed1],bx
	__asm mov	[g.Seed2],dx
	__asm mov	ecx,16
	__asm loop1:
	__asm xor	eax,eax
	__asm rol	bx,1
	__asm rcl	eax,1
	__asm rol	dx,1
	__asm rcl	eax,1
	__asm mov	[g.PtrArray+ecx-1],al
	__asm loop	loop1
	// for (idx = 0; idx < NUM_WORD4DIGS; idx++)
	__asm mov	ecx,NUM_WORD4DIGS	// ecx = idx
	__asm loop2:
	// init g.SeedArray
	__asm mov	eax, dword ptr [digs4digs_list+ecx*4-4]
	__asm mov	dword ptr [g.SeedArray],eax
	__asm mov	edi,offset ref_out	// edi = pout
	__asm mov	esi,offset ref_bits	// esi = pbits
	// for (i = 0; i < 5; i++)
	__asm mov	[i],5
	__asm xor	ebx,ebx		// bl = tmpPtr
	__asm loop3:
	__asm mov	eax,0Fh		// al = g.Var1
	__asm xor	edx,edx		// dl = g.Var2
	// for (j = 0; j < (2*4); j++)
	__asm mov	[j],2*4
	__asm loop4:
	// for (k = 0; k < 4; k++)
//	__asm xor	eax,eax
//	__asm xor	ebx,ebx
	// k=0
//	__asm mov	al,[g.Var1]
	__asm mov	bl,[g.PtrArray+eax]
	__asm mov	ah,[esi]
	__asm xor	ah,bl
	__asm and	ah,1
	__asm jne	next_value
	__asm xor	al,[g.SeedArray+ebx]
	__asm xor	al,dl
	__asm xor	al,[edi]
	__asm and	eax,0Fh
//	__asm mov	[g.Var1],al
	__asm shr	ebx,2
	__asm rcl	edx,1
	__asm inc	esi
	__asm inc	edi
	// k=1
//	__asm mov	al,[g.Var1]
	__asm mov	bl,[g.PtrArray+eax]
	__asm xor	al,[g.SeedArray+ebx]
	__asm xor	al,dl
	__asm xor	al,[edi]
	__asm and	eax,0Fh
//	__asm mov	[g.Var1],al
	__asm shr	ebx,2
	__asm rcl	edx,1
	__asm inc	edi
	// k=2
//	__asm mov	al,[g.Var1]
	__asm mov	bl,[g.PtrArray+eax]
	__asm xor	al,[g.SeedArray+ebx]
	__asm xor	al,dl
	__asm xor	al,[edi]
	__asm and	eax,0Fh
//	__asm mov	[g.Var1],al
	__asm shr	ebx,2
	__asm rcl	edx,1
	__asm inc	edi
	// k=3
//	__asm mov	al,[g.Var1]
	__asm mov	bl,[g.PtrArray+eax]
	__asm xor	al,[g.SeedArray+ebx]
	__asm xor	al,dl
	__asm xor	al,[edi]
	__asm and	eax,0Fh
//	__asm mov	[g.Var1],al
	__asm shr	ebx,2
	__asm rcl	edx,1
	__asm inc	edi
	// end for(k)
	__asm dec	[j]
	__asm jne	loop4
	// end for(j)
	__asm dec	[i]
	__asm jne	loop3
	// end for(i)
	__asm mov	ax,[word4digs_list+ecx*2-2]
	__asm mov	[g.Seed3],ax
	__asm push	ecx
	write_result_file(g.Seed1, g.Seed2, g.Seed3);
	__asm pop	ecx
	__asm next_value:
	__asm dec	ecx
	__asm jne	loop2
	// end for (idx)
#endif//USE_ASM_CODE
}

//------------------------------------------------------------------------------

void write_result_file(WORD	Seed1, WORD	Seed2, WORD Seed3)
{
	FILE	*fp;

	if ((fp = fopen(RESULT_FILE, "at")) != NULL) {
		fprintf(fp, "Found:\nSeed1=%04x\nSeed2=%04x\nSeed3=%04x\n\n",
			Seed1, Seed2, Seed3);
		fclose(fp);
	}
	printf("\n");
	printf("Found: Seed1=%04x Seed2=%04x Seed3=%04x\n",
		Seed1, Seed2, Seed3);
}

BOOL load_restart_file(BYTE *RefKey, BYTE *VerKey, int *restart_idx)
{
	RESTART_DATA	data;
	FILE	*fp;
	BOOL	res = FALSE;

	if ((fp = fopen(RESTART_FILE, "rb")) != NULL) {
		if (fread(&data, sizeof(data), 1, fp) == 1 &&
			memcmp(RefKey, data.RefKey, sizeof(data.RefKey)) == 0 &&
			memcmp(VerKey, data.VerKey, sizeof(data.VerKey)) == 0) {
			memcpy(crypt_out, data.crypt_out, sizeof(data.crypt_out));
			memcpy(crypt_bits, data.crypt_bits, sizeof(data.crypt_bits));
			*restart_idx = data.restart_idx;
			res = TRUE;
		}
		fclose(fp);
	}
	return res;
}

void save_restart_file(BYTE *RefKey, BYTE *VerKey, int restart_idx)
{
	RESTART_DATA	data;
	FILE	*fp;

	if ((fp = fopen(RESTART_FILE, "r+b")) != NULL ||
		(fp = fopen(RESTART_FILE, "wb")) != NULL) {
		memcpy(data.RefKey, RefKey, sizeof(data.RefKey));
		memcpy(data.VerKey, VerKey, sizeof(data.VerKey));
		memcpy(data.crypt_out, crypt_out, sizeof(data.crypt_out));
		memcpy(data.crypt_bits, crypt_bits, sizeof(data.crypt_bits));
		data.restart_idx = restart_idx;
		fwrite(&data, sizeof(data), 1, fp);
		fclose(fp);
	}
}

void unlink_restart_file()
{
	unlink(RESTART_FILE);
}

//------------------------------------------------------------------------------

int main(int argc, char *argv[])
{
#if 0
	static WORD MODAD = 0x7471;	//29809 = Demo Key
	static BYTE RefKey[8] = {'H','A','R','D','L','O','C','K'};
	static BYTE VerKey[8] = {0x18,0x4C,0x97,0xF0,0xC0,0x7A,0x08,0x88};
#else
	static WORD MODAD = 0x4798;	//18328 = Red Key
	static BYTE RefKey[8] = {0x68, 0xDF, 0xBD, 0x3C, 0x78, 0xCC, 0xCC, 0xAA};
	static BYTE VerKey[8] = {0x23, 0x0B, 0xFE, 0x04, 0x53, 0x8D, 0x9C, 0x3A};
#endif
	find_seed(RefKey, VerKey);
	printf("\ndone (press a key to exit)\n");
	getch();
	return 0;
}
