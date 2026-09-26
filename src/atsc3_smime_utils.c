//
//  atsc3_smime_utils.c
//  libatsc3
//
//  Created by Jason Justman on 11/17/20.
//  Copyright © 2020 Jason Justman. All rights reserved.
//

#include "atsc3_smime_utils.h"

int _ATSC3_SMIME_UTILS_INFO_ENABLED  = 1;
int _ATSC3_SMIME_UTILS_DEBUG_ENABLED = 1;
int _ATSC3_SMIME_UTILS_TRACE_ENABLED = 1;

atsc3_smime_entity_t* atsc3_smime_entity_new() {
	atsc3_smime_entity_t* atsc3_smime_entity = calloc(1, sizeof(atsc3_smime_entity_t));
	atsc3_smime_entity->atsc3_cms_entity = atsc3_cms_entity_new();

	return atsc3_smime_entity;
}

atsc3_smime_entity_t* atsc3_smime_entity_new_parse_from_file(const char* multipart_entity_filename) {
	atsc3_smime_entity_t* atsc3_smime_entity = atsc3_smime_entity_new();
	
	atsc3_smime_entity->raw_smime_payload_filename = strlcopy(multipart_entity_filename);
	atsc3_smime_entity->raw_smime_payload = block_Read_from_filename(multipart_entity_filename);
	
	if(!atsc3_smime_entity->raw_smime_payload) {
		_ATSC3_SMIME_UTILS_ERROR("atsc3_smime_entity_new_parse_from_file: unable to read raw smime payload from: %s", multipart_entity_filename);
		return NULL;
	}
	block_Rewind(atsc3_smime_entity->raw_smime_payload);

	//parse header
	//parse mime entity
	//parse signature
	
	return atsc3_smime_entity;
}

void atsc3_smime_entity_free(atsc3_smime_entity_t** atsc3_smime_entity_p) {
	if(atsc3_smime_entity_p) {
		atsc3_smime_entity_t* atsc3_smime_entity = *atsc3_smime_entity_p;
		if(atsc3_smime_entity) {

			if(atsc3_smime_entity->atsc3_cms_entity) {
				atsc3_cms_entity_free(&atsc3_smime_entity->atsc3_cms_entity);
			}

			if(atsc3_smime_entity->mime_version) {
				freeclean((void**)&atsc3_smime_entity->mime_version);
			}
			if(atsc3_smime_entity->content_type) {
				freeclean((void**)&atsc3_smime_entity->content_type);
			}
			if(atsc3_smime_entity->micalg) {
				freeclean((void**)&atsc3_smime_entity->micalg);
			}
			if(atsc3_smime_entity->boundary) {
				freeclean((void**)&atsc3_smime_entity->boundary);
			}
			
			if(atsc3_smime_entity->raw_smime_payload_filename) {
				freeclean((void**)&atsc3_smime_entity->raw_smime_payload_filename);
			}
			
			if(atsc3_smime_entity->raw_smime_payload) {
				block_Destroy(&atsc3_smime_entity->raw_smime_payload);
			}
			
			if(atsc3_smime_entity->cms_verified_extracted_mime_entity) {
				block_Destroy(&atsc3_smime_entity->cms_verified_extracted_mime_entity);
			}

			free(atsc3_smime_entity);
			atsc3_smime_entity = NULL;
		}
		
		*atsc3_smime_entity_p = NULL;
	}
}

atsc3_smime_validation_context_t* atsc3_smime_validation_context_new(atsc3_smime_entity_t* atsc3_smime_entity) {
	atsc3_smime_validation_context_t* atsc3_smime_validation_context = calloc(1, sizeof(atsc3_smime_validation_context_t));
	atsc3_smime_validation_context->atsc3_smime_entity = atsc3_smime_entity;
	atsc3_smime_validation_context->atsc3_cms_validation_context = atsc3_cms_validation_context_new(atsc3_smime_validation_context->atsc3_smime_entity->atsc3_cms_entity);
	
	return atsc3_smime_validation_context;
}

void atsc3_smime_validation_context_free(atsc3_smime_validation_context_t** atsc3_smime_validation_context_p) {
	if(atsc3_smime_validation_context_p) {
		atsc3_smime_validation_context_t* atsc3_smime_validation_context = *atsc3_smime_validation_context_p;
		if(atsc3_smime_validation_context) {

			bool has_called_atsc3_smime_entity_free = false;
			if(atsc3_smime_validation_context->atsc3_smime_entity) {
				atsc3_smime_entity_free(&atsc3_smime_validation_context->atsc3_smime_entity);
				has_called_atsc3_smime_entity_free = true;
			}

			if(atsc3_smime_validation_context->atsc3_cms_validation_context) {
				//jjustman-2022-09-25 - hack -
				if(has_called_atsc3_smime_entity_free) {
					atsc3_smime_validation_context->atsc3_cms_validation_context->atsc3_cms_entity = NULL;
				}

				atsc3_cms_validation_context_free(&atsc3_smime_validation_context->atsc3_cms_validation_context);
			}
			
			free(atsc3_smime_validation_context);
			atsc3_smime_validation_context = NULL;
		}
		
		*atsc3_smime_validation_context_p = NULL;
	}
}


void atsc3_smime_validation_context_set_cms_noverify(atsc3_smime_validation_context_t* atsc3_smime_validation_context, bool noverify_flag) {
	atsc3_cms_validation_context_set_cms_noverify(atsc3_smime_validation_context->atsc3_cms_validation_context, noverify_flag);
}

void atsc3_smime_validation_context_set_cms_no_content_verify(atsc3_smime_validation_context_t* atsc3_smime_validation_context, bool no_content_verify_flag) {
	atsc3_cms_validation_context_set_cms_no_content_verify(atsc3_smime_validation_context->atsc3_cms_validation_context, no_content_verify_flag);
}

atsc3_smime_validation_context_t* atsc3_smime_validation_context_certificate_payload_parse_from_file(atsc3_smime_validation_context_t* atsc3_smime_validation_context, const char* signing_certificate_filename) {
	//jjustman-2022-09-01 - TODO - fix me
	_ATSC3_SMIME_UTILS_ERROR("atsc3_smime_validation_context_certificate_payload_parse_from_file - method deprecated, exiting!");

	exit(1);

	return atsc3_smime_validation_context;
}

/*
 
 From LLS: CDT emission
 
 Data:
	   Version: 3 (0x2)
	   Serial Number: 11185070432223617944 (0x9b395a4c0c69e398)
   Signature Algorithm: sha256WithRSAEncryption
	   Issuer: C=US, O=A3SA, OU=Root 2020, CN=A3SA Root 2020
	   Validity
		   Not Before: Sep 18 01:58:07 2020 GMT
		   Not After : Sep 17 01:58:07 2025 GMT
	   Subject: C=US, O=A3SA, OU=Root 2020, CN=A3SA Root 2020
 */
atsc3_smime_validation_context_t* atsc3_smime_validation_context_certificate_payload_parse_from_file_with_root_fallback(atsc3_smime_validation_context_t* atsc3_smime_validation_context, const char* signing_certificate_filename) {
	//jjustman-2022-09-01 - TODO - fix me
	_ATSC3_SMIME_UTILS_ERROR("atsc3_smime_validation_context_certificate_payload_parse_from_file_with_root_fallback - method deprecated, exiting!");
	exit(1);

	return atsc3_smime_validation_context;
}

/*
 
 1.) read in full smime payload

	mbms_toi_filename = alc_packet_dump_to_object_get_filename_tsi_toi(udp_flow, 0, mbms_toi);

	block_Read_from_filename
 
 2.) extract out cms / multipart signature
 
 3.) process fragments as usual

	-> atsc3_mime_multipart_related_parser
 
	atsc3_sls_metadata_fragments_pending = atsc3_mbms_envelope_to_sls_metadata_fragments_parse_from_fdt_fp(fp_mbms);

 
 
 */

/*
 * Return the signed MIME entity of a multipart/signed S/MIME payload without
 * verifying the signature. The signature only authenticates the SLS; the
 * entity it covers (the multipart/related USBD/S-TSID/MPD) is plain text.
 * SMIME_read_CMS() hands that first body part back as a separate BIO for
 * detached signatures, which is exactly what CMS_verify() would copy out.
 */
static block_t* atsc3_smime_extract_unverified_payload(block_t* raw_smime_payload) {
	BIO* smime_in = NULL;
	BIO* signed_content = NULL;
	BIO* content_out = NULL;
	CMS_ContentInfo* cms = NULL;
	block_t* extracted = NULL;
	char copy_buf[4096];
	char* content_out_p = NULL;
	long content_out_len = 0;
	int n;

	block_Rewind(raw_smime_payload);
	smime_in = BIO_new_mem_buf(block_Get(raw_smime_payload), block_Remaining_size(raw_smime_payload));
	if(!smime_in) {
		goto cleanup;
	}

	cms = SMIME_read_CMS(smime_in, &signed_content);
	if(!cms || !signed_content) {
		_ATSC3_SMIME_UTILS_WARN("atsc3_smime_extract_unverified_payload: not a detached multipart/signed payload (cms: %p, content: %p)", cms, signed_content);
		goto cleanup;
	}

	content_out = BIO_new(BIO_s_mem());
	if(!content_out) {
		goto cleanup;
	}
	while((n = BIO_read(signed_content, copy_buf, sizeof(copy_buf))) > 0) {
		BIO_write(content_out, copy_buf, n);
	}

	content_out_len = BIO_get_mem_data(content_out, &content_out_p);
	if(content_out_len > 0) {
		extracted = block_Alloc(content_out_len);
		block_Write(extracted, (uint8_t*) content_out_p, content_out_len);
		block_Rewind(extracted);
	}

cleanup:
	if(content_out) {
		BIO_free(content_out);
	}
	if(signed_content) {
		BIO_free(signed_content);
	}
	if(cms) {
		CMS_ContentInfo_free(cms);
	}
	if(smime_in) {
		BIO_free(smime_in);
	}
	block_Rewind(raw_smime_payload);

	return extracted;
}

atsc3_smime_validation_context_t* atsc3_smime_validate_from_context(atsc3_smime_validation_context_t* atsc3_smime_validation_context) {

	//resync our raw binary payload
	if(atsc3_smime_validation_context->atsc3_smime_entity->atsc3_cms_entity->raw_binary_payload) {
		block_Destroy(&atsc3_smime_validation_context->atsc3_smime_entity->atsc3_cms_entity->raw_binary_payload);
	}

	atsc3_smime_validation_context->atsc3_smime_entity->atsc3_cms_entity->raw_binary_payload = block_Duplicate(atsc3_smime_validation_context->atsc3_smime_entity->raw_smime_payload);

	//call our cms validation call

	if(atsc3_cms_validate_from_context(atsc3_smime_validation_context->atsc3_cms_validation_context)) {
		atsc3_smime_validation_context->atsc3_smime_entity->cms_verified_extracted_mime_entity = block_Duplicate(atsc3_smime_validation_context->atsc3_smime_entity->atsc3_cms_entity->cms_verified_extracted_payload);
		return atsc3_smime_validation_context;
	}

	/*
	 * The no-verify flags are meant to disable validation, but
	 * atsc3_cms_validate_from_context() still needs the LLS CertificationData
	 * to build its certificate chain and returns NULL without it - so a
	 * receiver that never gets that table dropped every signed SLS, and with
	 * it all media. When the caller asked for no verification, honour that.
	 */
	if(atsc3_smime_validation_context->atsc3_cms_validation_context->cms_no_content_verify ||
	   atsc3_smime_validation_context->atsc3_cms_validation_context->cms_noverify) {
		block_t* unverified = atsc3_smime_extract_unverified_payload(atsc3_smime_validation_context->atsc3_smime_entity->raw_smime_payload);
		if(unverified) {
			_ATSC3_SMIME_UTILS_WARN("atsc3_smime_validate_from_context: signature not verified (no-verify requested), using signed payload as-is, len: %d", unverified->p_size);
			atsc3_smime_validation_context->atsc3_smime_entity->cms_verified_extracted_mime_entity = unverified;
			return atsc3_smime_validation_context;
		}
	}

	return NULL;
}

