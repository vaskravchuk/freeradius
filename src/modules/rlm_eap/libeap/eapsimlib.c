/*
 * eapsimlib.c    based upon draft-haverinen-pppext-eap-sim-11.txt.
 *
 * The development of the EAP/SIM support was funded by Internet Foundation
 * Austria (http://www.nic.at/ipa).
 *
 * code common to EAP-SIM clients and to servers.
 *
 * Version:     $Id$
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 *
 * Copyright 2000-2003,2006  The FreeRADIUS server project
 * Copyright 2003  Michael Richardson <mcr@sandelman.ottawa.on.ca>
 */

/*
 *  EAP-SIM PACKET FORMAT
 *  ------- ------ ------
 *
 * EAP Request and Response Packet Format
 * --- ------- --- -------- ------ ------
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |     Code      |  Identifier   |            Length             |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |     Type      |  SIM-Type     |   SIM-Length  |     value ... |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * with SIM-Type/SIM-Length/Value... repeating. SIM-Length is in units
 * of 32 bits, and includes the Sim-Type/Sim-Length fields.
 *
 * The SIM-Type's are mapped to ATTRIBUTE_EAP_SIM_BASE+Sim-type and
 * unmapped by these functions.
 *
 */

#include <freeradius-devel/ident.h>
RCSID("$Id$")

#include <freeradius-devel/autoconf.h>
#include <freeradius-devel/missing.h>
#include <freeradius-devel/libradius.h>
#include "eap_types.h"
#include "eap_sim.h"
#include <freeradius-devel/sha1.h>

/*
 * given a radius request with many attribues in the EAP-SIM range, build
 * them all into a single EAP-SIM body.
 *
 */
int map_eapsim_basictypes(RADIUS_PACKET *r, EAP_PACKET *ep)
{
	VALUE_PAIR       *vp;
	int               encoded_size;
	uint8_t          *encodedmsg, *attr;
	unsigned int      id, eapcode;
	unsigned char    *macspace, *append;
	int               appendlen;
	unsigned char     subtype;

	macspace = NULL;
	append = NULL;
	appendlen = 0;

	/*
	 * encodedmsg is now an EAP-SIM message.
	 * it might be too big for putting into an EAP-Type-SIM
	 *
	 */
	vp = pairfind(r->vps, ATTRIBUTE_EAP_SIM_SUBTYPE);
	if(vp == NULL)
	{
		subtype = eapsim_start;
	}
	else
	{
		subtype = vp->vp_integer;
	}

	vp = pairfind(r->vps, ATTRIBUTE_EAP_ID);
	if(vp == NULL)
	{
		id = ((int)getpid() & 0xff);
	}
	else
	{
		id = vp->vp_integer;
	}

	vp = pairfind(r->vps, ATTRIBUTE_EAP_CODE);
	if(vp == NULL)
	{
		eapcode = PW_EAP_REQUEST;
	}
	else
	{
		eapcode = vp->vp_integer;
	}

	/*
	 * take a walk through the attribute list to see how much space
	 * that we need to encode all of this.
	 */
	encoded_size = 0;
	for(vp = r->vps; vp != NULL; vp = vp->next)
	{
		int roundedlen;
		int vplen;

		if(vp->attribute < ATTRIBUTE_EAP_SIM_BASE ||
		   vp->attribute >= ATTRIBUTE_EAP_SIM_BASE+256)
		{
			continue;
		}

		vplen = vp->length;

		/*
		 * the AT_MAC attribute is a bit different, when we get to this
		 * attribute, we pull the contents out, save it for later
		 * processing, set the size to 16 bytes (plus 2 bytes padding).
		 *
 		 * At this point, we only care about the size.
		 */
		if(vp->attribute == ATTRIBUTE_EAP_SIM_BASE+PW_EAP_SIM_MAC) {
			vplen = 18;
		}

		/* round up to next multiple of 4, after taking in
		 * account the type and length bytes
		 */
		roundedlen = (vplen + 2 + 3) & ~3;
		encoded_size += roundedlen;
	}

	if (ep->code != PW_EAP_SUCCESS)
		ep->code = eapcode;
	ep->id = (id & 0xff);
	ep->type.type = PW_EAP_SIM;

	/*
	 * if no attributes were found, do very little.
	 *
	 */
	if(encoded_size == 0)
	{
	        encodedmsg = malloc(3);
		/* FIX: could be NULL */

		encodedmsg[0]=subtype;
		encodedmsg[1]=0;
		encodedmsg[2]=0;

		ep->type.length = 3;
		ep->type.data = encodedmsg;

		return 0;
	}


	/*
	 * figured out the length, so malloc some space for the results.
	 *
	 * Note that we do not bother going through an "EAP" stage, which
	 * is a bit strange compared to the unmap, which expects to see
	 * an EAP-SIM virtual attributes.
	 *
	 * EAP is 1-code, 1-identifier, 2-length, 1-type = 5 overhead.
	 *
	 * SIM code adds a subtype, and 2 bytes of reserved = 3.
	 *
	 */

	/* malloc space for it */

	encoded_size += 3;
	encodedmsg = malloc(encoded_size);
	if (encodedmsg == NULL) {
		radlog(L_ERR, "eapsim: out of memory allocating %d bytes", encoded_size+5);
		return 0;
	}
	memset(encodedmsg, 0, encoded_size);

	/*
	 * now walk the attributes again, sticking them in.
	 *
	 * we go three bytes into the encoded message, because there are two
	 * bytes of reserved, and we will fill the "subtype" in later.
	 *
	 */
	attr = encodedmsg+3;

	for(vp = r->vps; vp != NULL; vp = vp->next)
	{
		int roundedlen;

		if(vp->attribute < ATTRIBUTE_EAP_SIM_BASE ||
		   vp->attribute >= ATTRIBUTE_EAP_SIM_BASE+256)
		{
			continue;
		}

		/*
		 * the AT_MAC attribute is a bit different, when we get to this
		 * attribute, we pull the contents out, save it for later
		 * processing, set the size to 16 bytes (plus 2 bytes padding).
		 *
 		 * At this point, we put in zeros, and remember where the
		 * sixteen bytes go.
		 */
		if(vp->attribute == ATTRIBUTE_EAP_SIM_BASE+PW_EAP_SIM_MAC) {
			roundedlen = 20;
			memset(&attr[2], 0, 18);
			macspace = &attr[4];
			append = vp->vp_octets;
			appendlen = vp->length;
		}
		else {
			roundedlen = (vp->length + 2 + 3) & ~3;
			memset(attr, 0, roundedlen);
			memcpy(&attr[2], vp->vp_strvalue, vp->length);
		}
		attr[0] = vp->attribute - ATTRIBUTE_EAP_SIM_BASE;
		attr[1] = roundedlen >> 2;

		attr += roundedlen;
	}

	encodedmsg[0] = subtype;

	ep->type.length = encoded_size;
	ep->type.data = encodedmsg;

	/*
	 * if macspace was set and we have a key,
	 * then we should calculate the HMAC-SHA1 of the resulting EAP-SIM
	 * packet, appended with the value of append.
	 */
	vp = pairfind(r->vps, ATTRIBUTE_EAP_SIM_KEY);
	if(macspace != NULL && vp != NULL)
	{
		unsigned char   *buffer;
		eap_packet_t	*hdr;
		uint16_t         hmaclen, total_length = 0;
		unsigned char    sha1digest[20];

		total_length = EAP_HEADER_LEN + 1 + encoded_size;
		hmaclen = total_length + appendlen;
		buffer = (unsigned char *)malloc(hmaclen);
		hdr = (eap_packet_t *)buffer;
		if (!hdr) {
			radlog(L_ERR, "rlm_eap: out of memory");
			free(encodedmsg);
			return 0;
		}

		hdr->code = eapcode & 0xFF;
		hdr->id = (id & 0xFF);
		total_length = htons(total_length);
		memcpy(hdr->length, &total_length, sizeof(total_length));

		hdr->data[0] = PW_EAP_SIM;

		/* copy the data */
		memcpy(&hdr->data[1], encodedmsg, encoded_size);

		/* copy the nonce */
		memcpy(&hdr->data[encoded_size+1], append, appendlen);

		/* HMAC it! */
		fr_hmac_sha1(buffer, hmaclen,
			       vp->vp_octets, vp->length,
			       sha1digest);

		/* done with the buffer, free it */
		free(buffer);

		/* now copy the digest to where it belongs in the AT_MAC */
                /* note that it is truncated to 128-bits */
		memcpy(macspace, sha1digest, 16);
	}

	/* if we had an AT_MAC and no key, then fail */
	if(macspace != NULL && vp == NULL)
	{
		if(encodedmsg != NULL)
			free(encodedmsg);
		return 0;
	}

	return 1;
}

/*
 * given a radius request with an EAP-SIM body, decode it into TLV pairs
 *
 * return value is TRUE if it succeeded, false if there was something
 * wrong and the packet should be discarded.
 *
 */
int unmap_eapsim_basictypes(RADIUS_PACKET *r,
			    uint8_t *attr, unsigned int attrlen)
{
	VALUE_PAIR              *newvp;
	int                     eapsim_attribute;
	unsigned int            eapsim_len;
	int                     es_attribute_count;
	unsigned int		id_len;

	es_attribute_count=0;

	/* big enough to have even a single attribute */
	if(attrlen < 5) {
		radlog(L_ERR, "eap: EAP-Sim attribute too short: %d < 2", attrlen);
		return 0;
	}

	newvp = paircreate(ATTRIBUTE_EAP_SIM_SUBTYPE, PW_TYPE_INTEGER);
	if (!newvp) return 0;
	newvp->vp_integer = attr[0];
	newvp->length = 1;
	pairadd(&(r->vps), newvp);

	attr     += 3;
	attrlen  -= 3;

	/* now, loop processing each attribute that we find */
	while(attrlen > 0)
	{
		if(attrlen < 2) {
			radlog(L_ERR, "eap: EAP-Sim attribute %d too short: %d < 2", es_attribute_count, attrlen);
			return 0;
		}

		eapsim_attribute = attr[0];
		eapsim_len = attr[1] * 4;

		if(eapsim_len > attrlen) {
			radlog(L_ERR, "eap: EAP-Sim attribute %d (no.%d) has length longer than data (%d > %d)"
			       , eapsim_attribute
			       , es_attribute_count, eapsim_len, attrlen);
			return 0;
		}

		if(eapsim_len > MAX_STRING_LEN) {
			eapsim_len = MAX_STRING_LEN;
		}
		if (eapsim_len < 2) {
			radlog(L_ERR, "eap: EAP-Sim attribute %d (no.%d) has length too small",
			       eapsim_attribute, es_attribute_count);
			       return 0;
		}

		/* AT_IDENTITY has special format */
		if (eapsim_attribute == PW_EAP_SIM_IDENTITY) {
			if (eapsim_len < 4) {
				radlog(L_ERR, "eap: EAP-Sim AT_IDENTITY (no.%d) has length too small",
					es_attribute_count);
				goto loop_end;
			}
			id_len = (attr[2] << 8) + attr[3];
			if (4 + id_len > eapsim_len) {
				radlog(L_ERR, "eap: EAP-Sim AT_IDENTITY (no.%d) invalid length",
					es_attribute_count);
				goto loop_end;
			}
		}

		newvp = paircreate(eapsim_attribute+ATTRIBUTE_EAP_SIM_BASE, PW_TYPE_OCTETS);
		switch (eapsim_attribute) {
		case PW_EAP_SIM_IDENTITY:
			memcpy(newvp->vp_strvalue, &attr[4], id_len);
			newvp->length = id_len;
			break;
		default:
			memcpy(newvp->vp_strvalue, &attr[2], eapsim_len-2);
			newvp->length = eapsim_len-2;
		}
		pairadd(&(r->vps), newvp);
		newvp = NULL;

	loop_end:
		/* advance pointers, decrement length */
		attr += eapsim_len;
		attrlen  -= eapsim_len;
		es_attribute_count++;
	}
	return 1;
}

/*
 * calculate the MAC for the EAP message, given the key.
 * The "extra" will be appended to the EAP message and included in the
 * HMAC.
 *
 */
int
eapsim_checkmac(VALUE_PAIR *rvps,
		uint8_t key[EAPSIM_AUTH_SIZE],
		uint8_t *extra, int extralen,
		uint8_t calcmac[20])
{
	int ret;
	eap_packet_t *e;
	uint8_t *buffer;
	int elen,len;
	VALUE_PAIR *mac;

	mac = pairfind(rvps, ATTRIBUTE_EAP_SIM_BASE+PW_EAP_SIM_MAC);

	if(mac == NULL
	   || mac->length != 18) {
		/* can't check a packet with no AT_MAC attribute */
		return 0;
	}

	/* get original copy of EAP message, note that it was sanitized
	 * to have a valid length, which we depend upon.
	 */
	e = eap_vp2packet(rvps);

	if(e == NULL)
	{
		return 0;
	}

	/* make copy big enough for everything */
	elen = e->length[0] * 256 + e->length[1];
	len = elen + extralen;

	buffer = malloc(len);
	if(buffer == NULL)
	{
		free(e);
		return 0;
	}

	memcpy(buffer, e, elen);
	memcpy(buffer+elen, extra, extralen);

	/*
	 * now look for the AT_MAC attribute in the copy of the buffer
	 * and make sure that the checksum is zero.
	 *
	 */
	{
		uint8_t *attr;

		/* first attribute is 8 bytes into the EAP packet.
		 * 4 bytes for EAP, 1 for type, 1 for subtype, 2 reserved.
		 */
		attr = buffer+8;
		while(attr < (buffer+elen)) {
			if(attr[0] == PW_EAP_SIM_MAC) {
				/* zero the data portion, after making sure
				 * the size is >=5. Maybe future versions.
				 * will use more bytes, so be liberal.
				 */
				if(attr[1] < 5) {
					ret = 0;
					goto done;
				}
				memset(&attr[4], 0, (attr[1]-1)*4);
			}
			/* advance the pointer */
			attr += attr[1]*4;
		}
	}

	/* now, HMAC-SHA1 it with the key. */
	fr_hmac_sha1(buffer, len,
		       key, 16,
		       calcmac);

	if(memcmp(&mac->vp_strvalue[2], calcmac, 16) == 0)	{
		ret = 1;
	} else {
		ret = 0;
	}

 done:
	free(e);
	free(buffer);
	return(ret);
}

/*
 * definitions changed to take a buffer for unknowns
 * as this is more thread safe.
 */
const char *simstates[]={ "init", "start", NULL };

const char *sim_state2name(enum eapsim_clientstates state,
			   char *statenamebuf,
			   int   statenamebuflen)
{
	if(state >= eapsim_client_maxstates)
	{
		snprintf(statenamebuf, statenamebuflen,
			 "eapstate:%d", state);
		return statenamebuf;
	}
	else
	{
		return simstates[state];
	}
}

const char *subtypes[]={ "subtype0", "subtype1", "subtype2", "subtype3",
			 "subtype4", "subtype5", "subtype6", "subtype7",
			 "subtype8", "subtype9",
			 "start",
			 "challenge",
			 "notification",
			 "reauth",
			 "client-error",
			 NULL };

const char *sim_subtype2name(enum eapsim_subtype subtype,
			     char *subtypenamebuf,
			     int   subtypenamebuflen)
{
	if(subtype >= eapsim_max_subtype)
	{
		snprintf(subtypenamebuf, subtypenamebuflen,
			 "illegal-subtype:%d", subtype);
		return subtypenamebuf;
	}
	else
	{
		return subtypes[subtype];
	}
}
