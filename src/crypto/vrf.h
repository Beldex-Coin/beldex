// See vrf.c for documentation
#ifndef VRF_H
#define VRF_H

#ifdef __cplusplus
extern "C" {
#endif

int vrf_prove(unsigned char proof[80], const unsigned char skpk[64], const unsigned char *msg, unsigned long long msglen);
int vrf_verify(unsigned char output[64], const unsigned char pk[32], const unsigned char proof[80], const unsigned char *msg, unsigned long long msglen);

int vrf_proof_to_hash(unsigned char hash[64], const unsigned char proof[80]); // Doesn't verify the proof; always use vrf_verify instead (unless the proof is one you just created yourself with vrf_prove)
int verify_vrf_output_and_get_fraction(unsigned char output[64], mpf_t fraction, double tau, double W);
bool verify_vrf_output_with_threshold(unsigned char output[64], double tau, double W);
int cryptographic_sortition(unsigned char output[64], unsigned char proof[80], 
					const unsigned char skpk[64], 
					const unsigned char *msg,
					unsigned long long msglen,
					double tau,
					double W
					);
                    
int sortition_verify(const unsigned char pk[32],
	   			unsigned char proof[80],
	   			const unsigned char *msg, 
	   			unsigned long long msglen,
	   			double tau,
	   			double W);
void bytesToHexString(const unsigned char *bytes, char *hex_str, size_t size);

#ifdef __cplusplus
}
#endif

#endif // VRF_H
