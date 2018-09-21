/* ezxml.c
 *
 * Copyright 2004-2006 Aaron Voisine <aaron@voisine.org>
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#ifndef EZXML_NOMMAP
#include <sys/mman.h>
#endif
#include <sys/stat.h>

#include "../include/xmlparse.h"

#define EZXML_WS   "\t\r\n "  // whitespace
#define EZXML_ERRL 128        // maximum error string length

#define EZXML_BUFSIZE 1024	// Size of internal memory buffers
#define EZXML_NAMEM   0x80	// Flag set if node name is malloc'ed
#define EZXML_TXTM    0x40	// Flag set if node's inner text is malloced
#define EZXML_DUP     0x20	// Flag set if node's attribute names and values are strdup'ed

struct XML::Root : public XML
{
	/* Additional data for the root element */
	
	Root(const char *name);
	~Root();

	XML *cur;          // current xml tree insertion point
	char *m;              // original xml string
	size_t len;           // length of allocated memory for mmap, -1 for malloc
	char *u;              // UTF-8 conversion of string if original was UTF-16
	char *s;              // start of work area
	char *e;              // end of work area
	char **ent;           // general entities (ampersand sequences)
	char ***default_attrs;// default attributes
	char ***pi;           // processing instructions
	short standalone;     // non-zero if <?xml standalone="yes"?>
	char err[EZXML_ERRL]; // error string
};

char *EZXML_NIL[] = { NULL }; // empty, null terminated array of strings

// sets a flag for the given tag and returns the tag
XML *ezxml_set_flag(XML *node, short flag)
{
	if (node) node->flags |= flag;
	return node;
}

// returns the first child tag with the given name or NULL if not found
XML *XML :: get_child(const char *name)
{
	XML *xml = this->child;
	while (xml && strcmp(name, xml->name)) xml = xml->sibling;
	return xml;
}

// returns the Nth tag with the same name in the same subsection or NULL if not
// found
XML *ezxml_idx(XML *node, int idx)
{
	for (; node != NULL && idx > 0; idx--)
	{
		node = node->next;
	}
	
	return node;
}

const char *XML :: get_attr(const char *attr)
{
	/* Search node */
	if (this->get_node_attr(attr) != NULL)
		return this->get_node_attr(attr);
	
	/* Search defaults */
	if (XML::get_default_attr(XML::get_root(this), this->name, attr) != NULL)
		return XML::get_default_attr(XML::get_root(this), this->name, attr);
	
	return NULL;
}

const char *XML :: get_node_attr(const char *name)
{
	/* Get the value of the attribute with the	*
	 * given name in the node. Returns NULL if	*
	 * not found. DOES ACCOUNT FOR DEFAULT		*
	 * ATTRIBUTES.								*/
	
	XML::Root * root = (XML::Root *) this;

	if (this->attr == NULL) return NULL;
	
	/* Go through all of the node's attributes	*
	 * checking whether their name matches.		*/
	for (char **current_name = this->attr; *current_name != NULL; current_name += 2)	// We have to increment the pointer by two every time because the pointers keep alternating between the name and the value.
	{
		if (strcmp(name, *current_name) == 0)
		{
			return *(++current_name);	// Return the pointer to the attribute value, which comes after the the pointer to its name.
		}
	}
	
	return NULL;
}

const char *XML :: get_default_attr(XML::Root *root, const char *tag, const char *attr)
{
	int i, j = 0;
	
	for (i = 0; root->default_attrs[i] && strcmp(tag, root->default_attrs[i][0]); i++);
	
	if (! root->default_attrs[i]) return NULL; // no matching default attributes
	
	
	while (root->default_attrs[i][j] && strcmp(attr, root->default_attrs[i][j]))
	{
		j += 3;
	}
	
	return (root->default_attrs[i][j]) ? root->default_attrs[i][j + 1] : NULL; // found default
}

// same as ezxml_get but takes an already initialized va_list
XML *ezxml_vget(XML *node, va_list ap)
{
	char *name = va_arg(ap, char *);
	int idx = -1;

	if (name && *name) {
		idx = va_arg(ap, int);    
		node = node->get_child(name);
	}
	return (idx < 0) ? node : ezxml_vget(ezxml_idx(node, idx), ap);
}

// Traverses the xml tree to retrieve a specific subtag. Takes a variable
// length list of tag names and indexes. The argument list must be terminated
// by either an index of -1 or an empty string tag name. Example: 
// title = ezxml_get(library, "shelf", 0, "book", 2, "title", -1);
// This retrieves the title of the 3rd book on the 1st shelf of library.
// Returns NULL if not found.
XML *XML :: get(XML *node, ...)
{
	va_list ap;
	XML *ret;

	va_start(ap, node);
	ret = ezxml_vget(node, ap);
	va_end(ap);
	return ret;
}

XML::Root *XML :: get_root(XML *node)
{
	/* Get the root node of the given node's tree */
	
	while (node->parent != NULL)
	{
		node = node->parent;
	}
	
	return (XML::Root *) node;
}

// returns a null terminated array of processing instructions for the given
// target
const char **ezxml_pi(XML *node, const char *target)
{
	XML::Root * root = (XML::Root *) node;
	int i = 0;

	if (! root) return (const char **)EZXML_NIL;
	while (root->parent) root = (XML::Root *)root->parent; // root tag
	while (root->pi[i] && strcmp(target, root->pi[i][0])) i++; // find target
	return (const char **)((root->pi[i]) ? root->pi[i] + 1 : EZXML_NIL);
}

// set an error string and return root
XML *ezxml_err(XML::Root * root, char *s, const char *err, ...)
{
	va_list ap;
	int line = 1;
	char *t, fmt[EZXML_ERRL];
	
	for (t = root->s; t < s; t++) if (*t == '\n') line++;
	snprintf(fmt, EZXML_ERRL, "[error near line %d]: %s", line, err);

	va_start(ap, err);
	vsnprintf(root->err, EZXML_ERRL, fmt, ap);
	va_end(ap);

	return root;
}

// Recursively decodes entity and character references and normalizes new lines
// ent is a null terminated array of alternating entity names and values. set t
// to '&' for general entity decoding, '%' for parameter entity decoding, 'c'
// for cdata sections, ' ' for attribute normalization, or '*' for non-cdata
// attribute normalization. Returns s, or if the decoded string is longer than
// s, returns a malloced string that must be freed.
char *ezxml_decode(char *s, char **ent, char t)
{
	char *e, *r = s, *m = s;
	long b, c, d, l;

	for (; *s; s++) { // normalize line endings
		while (*s == '\r') {
			*(s++) = '\n';
			if (*s == '\n') memmove(s, (s + 1), strlen(s));
		}
	}
	
	for (s = r; ; ) {
		while (*s && *s != '&' && (*s != '%' || t != '%') && !isspace(*s)) s++;

		if (! *s) break;
		else if (t != 'c' && ! strncmp(s, "&#", 2)) { // character reference
			if (s[2] == 'x') c = strtol(s + 3, &e, 16); // base 16
			else c = strtol(s + 2, &e, 10); // base 10
			if (! c || *e != ';') { s++; continue; } // not a character ref

			if (c < 0x80) *(s++) = c; // US-ASCII subset
			else { // multi-byte UTF-8 sequence
				for (b = 0, d = c; d; d /= 2) b++; // number of bits in c
				b = (b - 2) / 5; // number of bytes in payload
				*(s++) = (0xFF << (7 - b)) | (c >> (6 * b)); // head
				while (b) *(s++) = 0x80 | ((c >> (6 * --b)) & 0x3F); // payload
			}

			memmove(s, strchr(s, ';') + 1, strlen(strchr(s, ';')));
		}
		else if ((*s == '&' && (t == '&' || t == ' ' || t == '*')) ||
				 (*s == '%' && t == '%')) { // entity reference
			for (b = 0; ent[b] && strncmp(s + 1, ent[b], strlen(ent[b]));
				 b += 2); // find entity in entity list

			if (ent[b++]) { // found a match
				if ((c = strlen(ent[b])) - 1 > (e = strchr(s, ';')) - s) {
					l = (d = (s - r)) + c + strlen(e); // new length
					r = (r == m) ? strcpy((char *) malloc(l), r) : (char *) realloc(r, l);
					e = strchr((s = r + d), ';'); // fix up pointers
				}

				memmove(s + c, e + 1, strlen(e)); // shift rest of string
				strncpy(s, ent[b], c); // copy in replacement text
			}
			else s++; // not a known entity
		}
		else if ((t == ' ' || t == '*') && isspace(*s)) *(s++) = ' ';
		else s++; // no decoding needed
	}

	if (t == '*') { // normalize spaces for non-cdata attributes
		for (s = r; *s; s++) {
			if ((l = strspn(s, " "))) memmove(s, s + l, strlen(s + l) + 1);
			while (*s && *s != ' ') s++;
		}
		if (--s >= r && *s == ' ') *s = '\0'; // trim any trailing space
	}
	return r;
}

// called when parser finds start of new tag
void ezxml_open_tag(XML::Root * root, char *name, char **attr)
{
	XML *xml = root->cur;
	
	if (xml->name) xml = xml->add_child(name, strlen(xml->txt));
	else xml->name = name; // first open tag

	xml->attr = attr;
	root->cur = xml; // update tag insertion point
}

// called when parser finds character content between open and closing tag
void ezxml_char_content(XML::Root * root, char *s, size_t len, char t)
{
	XML *node = root->cur;
	char *m = s;
	size_t l;

	if (! node || ! node->name || ! len) return; // sanity check

	s[len] = '\0'; // null terminate text (calling functions anticipate this)
	len = strlen(s = ezxml_decode(s, root->ent, t)) + 1;

	if (! *(node->txt)) node->txt = s; // initial character content
	else { // allocate our own memory and make a copy
		node->txt = (node->flags & EZXML_TXTM) // allocate some space
				   ? (char *) realloc(node->txt, (l = strlen(node->txt)) + len)
				   : strcpy((char *) malloc((l = strlen(node->txt)) + len), node->txt);
		strcpy(node->txt + l, s); // add new char content
		if (s != m) free(s); // free s if it was malloced by ezxml_decode()
	}

	if (node->txt != m) ezxml_set_flag(node, EZXML_TXTM);
}

// called when parser finds closing tag
XML *ezxml_close_tag(XML::Root * root, char *name, char *s)
{
	if (! root->cur || ! root->cur->name || strcmp(name, root->cur->name))
		return ezxml_err((XML::Root *) root, s, "unexpected closing tag </%s>", name);

	root->cur = root->cur->parent;
	return NULL;
}

// checks for circular entity references, returns non-zero if no circular
// references are found, zero otherwise
int ezxml_ent_ok(char *name, char *s, char **ent)
{
	int i;

	for (; ; s++) {
		while (*s && *s != '&') s++; // find next entity reference
		if (! *s) return 1;
		if (! strncmp(s + 1, name, strlen(name))) return 0; // circular ref.
		for (i = 0; ent[i] && strncmp(ent[i], s + 1, strlen(ent[i])); i += 2);
		if (ent[i] && ! ezxml_ent_ok(name, ent[i + 1], ent)) return 0;
	}
}

// called when the parser finds a processing instruction
void ezxml_proc_inst(XML::Root * root, char *s, size_t len)
{
	int i = 0, j = 1;
	char *target = s;

	s[len] = '\0'; // null terminate instruction
	if (*(s += strcspn(s, EZXML_WS))) {
		*s = '\0'; // null terminate target
		s += strspn(s + 1, EZXML_WS) + 1; // skip whitespace after target
	}

	if (! strcmp(target, "xml")) { // <?xml ... ?>
		if ((s = strstr(s, "standalone")) && ! strncmp(s + strspn(s + 10,
			EZXML_WS "='\"") + 10, "yes", 3)) root->standalone = 1;
		return;
	}

	if (! root->pi[0]) *(root->pi = (char ***) malloc(sizeof(char **))) = NULL; //first pi

	while (root->pi[i] && strcmp(target, root->pi[i][0])) i++; // find target
	if (! root->pi[i]) { // new target
		root->pi = (char ***) realloc(root->pi, sizeof(char **) * (i + 2));
		root->pi[i] = (char **) malloc(sizeof(char *) * 3);
		root->pi[i][0] = target;
		root->pi[i][1] = (char *)(root->pi[i + 1] = NULL); // terminate pi list
		root->pi[i][2] = strdup(""); // empty document position list
	}

	while (root->pi[i][j]) j++; // find end of instruction list for this target
	root->pi[i] = (char **) realloc(root->pi[i], sizeof(char *) * (j + 3));
	root->pi[i][j + 2] = (char *) realloc(root->pi[i][j + 1], j + 1);
	strcpy(root->pi[i][j + 2] + j - 1, (root->name) ? ">" : "<");
	root->pi[i][j + 1] = NULL; // null terminate pi list for this target
	root->pi[i][j] = s; // set instruction
}

// called when the parser finds an internal doctype subset
short ezxml_internal_dtd(XML::Root * root, char *s, size_t len)
{
	char q, *c, *t, *n = NULL, *v, **ent, **pe;
	int i, j;
	
	pe = (char **) memcpy(malloc(sizeof(EZXML_NIL)), EZXML_NIL, sizeof(EZXML_NIL));

	for (s[len] = '\0'; s; ) {
		while (*s && *s != '<' && *s != '%') s++; // find next declaration

		if (! *s) break;
		else if (! strncmp(s, "<!ENTITY", 8)) { // parse entity definitions
			c = s += strspn(s + 8, EZXML_WS) + 8; // skip white space separator
			n = s + strspn(s, EZXML_WS "%"); // find name
			*(s = n + strcspn(n, EZXML_WS)) = ';'; // append ; to name

			v = s + strspn(s + 1, EZXML_WS) + 1; // find value
			if ((q = *(v++)) != '"' && q != '\'') { // skip externals
				s = strchr(s, '>');
				continue;
			}

			for (i = 0, ent = (*c == '%') ? pe : root->ent; ent[i]; i++);
			ent = (char **) realloc(ent, (i + 3) * sizeof(char *)); // space for next ent
			if (*c == '%') pe = ent;
			else root->ent = ent;

			*(++s) = '\0'; // null terminate name
			if ((s = strchr(v, q))) *(s++) = '\0'; // null terminate value
			ent[i + 1] = ezxml_decode(v, pe, '%'); // set value
			ent[i + 2] = NULL; // null terminate entity list
			if (! ezxml_ent_ok(n, ent[i + 1], ent)) { // circular reference
				if (ent[i + 1] != v) free(ent[i + 1]);
				ezxml_err((XML::Root *) root, v, "circular entity declaration &%s", n);
				break;
			}
			else ent[i] = n; // set entity name
		}
		else if (! strncmp(s, "<!ATTLIST", 9)) { // parse default attributes
			t = s + strspn(s + 9, EZXML_WS) + 9; // skip whitespace separator
			if (! *t) { ezxml_err((XML::Root *) root, t, "unclosed <!ATTLIST"); break; }
			if (*(s = t + strcspn(t, EZXML_WS ">")) == '>') continue;
			else *s = '\0'; // null terminate tag name
			for (i = 0; root->default_attrs[i] && strcmp(n, root->default_attrs[i][0]); i++);

			while (*(n = ++s + strspn(s, EZXML_WS)) && *n != '>') {
				if (*(s = n + strcspn(n, EZXML_WS))) *s = '\0'; // attr name
				else { ezxml_err((XML::Root *) root, t, "malformed <!ATTLIST"); break; }

				s += strspn(s + 1, EZXML_WS) + 1; // find next token
				c = (char *) (strncmp(s, "CDATA", 5) ? "*" : " "); // is it cdata?
				if (! strncmp(s, "NOTATION", 8))
					s += strspn(s + 8, EZXML_WS) + 8;
				s = (*s == '(') ? strchr(s, ')') : s + strcspn(s, EZXML_WS);
				if (! s) { ezxml_err((XML::Root *) root, t, "malformed <!ATTLIST"); break; }

				s += strspn(s, EZXML_WS ")"); // skip white space separator
				if (! strncmp(s, "#FIXED", 6))
					s += strspn(s + 6, EZXML_WS) + 6;
				if (*s == '#') { // no default value
					s += strcspn(s, EZXML_WS ">") - 1;
					if (*c == ' ') continue; // cdata is default, nothing to do
					v = NULL;
				}
				else if ((*s == '"' || *s == '\'')  &&  // default value
						 (s = strchr(v = s + 1, *s))) *s = '\0';
				else { ezxml_err((XML::Root *) root, t, "malformed <!ATTLIST"); break; }

				if (! root->default_attrs[i]) { // new tag name
					root->default_attrs = (! i) ? (char ***) malloc(2 * sizeof(char **))
									   : (char ***) realloc(root->default_attrs,
												 (i + 2) * sizeof(char **));
					root->default_attrs[i] = (char **) malloc(2 * sizeof(char *));
					root->default_attrs[i][0] = t; // set tag name
					root->default_attrs[i][1] = (char *)(root->default_attrs[i + 1] = NULL);
				}

				for (j = 1; root->default_attrs[i][j]; j += 3); // find end of list
				root->default_attrs[i] = (char **) realloc(root->default_attrs[i],
										(j + 4) * sizeof(char *));

				root->default_attrs[i][j + 3] = NULL; // null terminate list
				root->default_attrs[i][j + 2] = c; // is it cdata?
				root->default_attrs[i][j + 1] = (v) ? ezxml_decode(v, root->ent, *c)
										   : NULL;
				root->default_attrs[i][j] = n; // attribute name 
			}
		}
		else if (! strncmp(s, "<!--", 4)) s = strstr(s + 4, "-->"); // comments
		else if (! strncmp(s, "<?", 2)) { // processing instructions
			if ((s = strstr(c = s + 2, "?>")))
				ezxml_proc_inst(root, c, s++ - c);
		}
		else if (*s == '<') s = strchr(s, '>'); // skip other declarations
		else if (*(s++) == '%' && ! root->standalone) break;
	}

	free(pe);
	return ! *root->err;
}

// Converts a UTF-16 string to UTF-8. Returns a new string that must be freed
// or NULL if no conversion was needed.
char *ezxml_str2utf8(char **s, size_t *len)
{
	char *u;
	size_t l = 0, sl, max = *len;
	long c, d;
	int b, be = (**s == '\xFE') ? 1 : (**s == '\xFF') ? 0 : -1;

	if (be == -1) return NULL; // not UTF-16

	u = (char *) malloc(max);
	for (sl = 2; sl < *len - 1; sl += 2) {
		c = (be) ? (((*s)[sl] & 0xFF) << 8) | ((*s)[sl + 1] & 0xFF)  //UTF-16BE
				 : (((*s)[sl + 1] & 0xFF) << 8) | ((*s)[sl] & 0xFF); //UTF-16LE
		if (c >= 0xD800 && c <= 0xDFFF && (sl += 2) < *len - 1) { // high-half
			d = (be) ? (((*s)[sl] & 0xFF) << 8) | ((*s)[sl + 1] & 0xFF)
					 : (((*s)[sl + 1] & 0xFF) << 8) | ((*s)[sl] & 0xFF);
			c = (((c & 0x3FF) << 10) | (d & 0x3FF)) + 0x10000;
		}

		while (l + 6 > max) u = (char *) realloc(u, max += EZXML_BUFSIZE);
		if (c < 0x80) u[l++] = c; // US-ASCII subset
		else { // multi-byte UTF-8 sequence
			for (b = 0, d = c; d; d /= 2) b++; // bits in c
			b = (b - 2) / 5; // bytes in payload
			u[l++] = (0xFF << (7 - b)) | (c >> (6 * b)); // head
			while (b) u[l++] = 0x80 | ((c >> (6 * --b)) & 0x3F); // payload
		}
	}
	return *s = (char *) realloc(u, *len = l);
}

// frees a tag attribute list
void ezxml_free_attr(char **attr) {
	int i = 0;
	char *m;
	
	if (! attr || attr == EZXML_NIL) return; // nothing to free
	while (attr[i]) i += 2; // find end of attribute list
	m = attr[i + 1]; // list of which names and values are malloced
	for (i = 0; m[i]; i++) {
		if (m[i] & EZXML_NAMEM) free(attr[i * 2]);
		if (m[i] & EZXML_TXTM) free(attr[(i * 2) + 1]);
	}
	free(m);
	free(attr);
}

// parse the given xml string and return an ezxml structure
XML *XML :: parse_str(char *s, size_t len)
{
	XML::Root * root = new XML::Root(NULL);
	char q, e, *d, **attr, **a = NULL; // initialize a to avoid compile warning
	int l, i, j;

	root->m = s;
	if (! len) return ezxml_err((XML::Root *) root, NULL, "root tag missing");
	root->u = ezxml_str2utf8(&s, &len); // convert utf-16 to utf-8
	root->e = (root->s = s) + len; // record start and end of work area
	
	e = s[len - 1]; // save end char
	s[len - 1] = '\0'; // turn end char into null terminator

	while (*s && *s != '<') s++; // find first tag
	if (! *s) return ezxml_err((XML::Root *) root, s, "root tag missing");

	for (; ; ) {
		attr = (char **)EZXML_NIL;
		d = ++s;
		
		if (isalpha(*s) || *s == '_' || *s == ':' || *s < '\0') { // new tag
			if (! root->cur)
				return ezxml_err((XML::Root *) root, d, "markup outside of root element");

			s += strcspn(s, EZXML_WS "/>");
			while (isspace(*s)) *(s++) = '\0'; // null terminate tag name
  
			if (*s && *s != '/' && *s != '>') // find tag in default attr list
				for (i = 0; (a = root->default_attrs[i]) && strcmp(a[0], d); i++);

			for (l = 0; *s && *s != '/' && *s != '>'; l += 2) { // new attrib
				attr = (l) ? (char **) realloc(attr, (l + 4) * sizeof(char *))
						   : (char **) malloc(4 * sizeof(char *)); // allocate space
				attr[l + 3] = (l) ? (char *) realloc(attr[l + 1], (l / 2) + 2)
								  : (char *) malloc(2); // mem for list of maloced vals
				strcpy(attr[l + 3] + (l / 2), " "); // value is not malloced
				attr[l + 2] = NULL; // null terminate list
				attr[l + 1] = ""; // temporary attribute value
				attr[l] = s; // set attribute name

				s += strcspn(s, EZXML_WS "=/>");
				if (*s == '=' || isspace(*s)) { 
					*(s++) = '\0'; // null terminate tag attribute name
					q = *(s += strspn(s, EZXML_WS "="));
					if (q == '"' || q == '\'') { // attribute value
						attr[l + 1] = ++s;
						while (*s && *s != q) s++;
						if (*s) *(s++) = '\0'; // null terminate attribute val
						else {
							ezxml_free_attr(attr);
							return ezxml_err((XML::Root *) root, d, "missing %c", q);
						}

						for (j = 1; a && a[j] && strcmp(a[j], attr[l]); j +=3);
						attr[l + 1] = ezxml_decode(attr[l + 1], root->ent, (a
												   && a[j]) ? *a[j + 2] : ' ');
						if (attr[l + 1] < d || attr[l + 1] > s)
							attr[l + 3][l / 2] = EZXML_TXTM; // value malloced
					}
				}
				while (isspace(*s)) s++;
			}

			if (*s == '/') { // self closing tag
				*(s++) = '\0';
				if ((*s && *s != '>') || (! *s && e != '>')) {
					if (l) ezxml_free_attr(attr);
					return ezxml_err((XML::Root *) root, d, "missing >");
				}
				ezxml_open_tag(root, d, attr);
				ezxml_close_tag(root, d, s);
			}
			else if ((q = *s) == '>' || (! *s && e == '>')) { // open tag
				*s = '\0'; // temporarily null terminate tag name
				ezxml_open_tag(root, d, attr);
				*s = q;
			}
			else {
				if (l) ezxml_free_attr(attr);
				return ezxml_err((XML::Root *) root, d, "missing >"); 
			}
		}
		else if (*s == '/') { // close tag
			s += strcspn(d = s + 1, EZXML_WS ">") + 1;
			if (! (q = *s) && e != '>') return ezxml_err((XML::Root *) root, d, "missing >");
			*s = '\0'; // temporarily null terminate tag name
			if (ezxml_close_tag(root, d, s)) return root;
			if (isspace(*s = q)) s += strspn(s, EZXML_WS);
		}
		else if (! strncmp(s, "!--", 3)) { // xml comment
			if (! (s = strstr(s + 3, "--")) || (*(s += 2) != '>' && *s) ||
				(! *s && e != '>')) return ezxml_err((XML::Root *) root, d, "unclosed <!--");
		}
		else if (! strncmp(s, "![CDATA[", 8)) { // cdata
			if ((s = strstr(s, "]]>")))
				ezxml_char_content(root, d + 8, (s += 2) - d - 10, 'c');
			else return ezxml_err((XML::Root *) root, d, "unclosed <![CDATA[");
		}
		else if (! strncmp(s, "!DOCTYPE", 8)) { // dtd
			for (l = 0; *s && ((! l && *s != '>') || (l && (*s != ']' || 
				 *(s + strspn(s + 1, EZXML_WS) + 1) != '>')));
				 l = (*s == '[') ? 1 : l) s += strcspn(s + 1, "[]>") + 1;
			if (! *s && e != '>')
				return ezxml_err((XML::Root *) root, d, "unclosed <!DOCTYPE");
			d = (l) ? strchr(d, '[') + 1 : d;
			if (l && ! ezxml_internal_dtd(root, d, s++ - d)) return root;
		}
		else if (*s == '?') { // <?...?> processing instructions
			do { s = strchr(s, '?'); } while (s && *(++s) && *s != '>');
			if (! s || (! *s && e != '>')) 
				return ezxml_err((XML::Root *) root, d, "unclosed <?");
			else ezxml_proc_inst(root, d + 1, s - d - 2);
		}
		else return ezxml_err((XML::Root *) root, d, "unexpected <");
		
		if (! s || ! *s) break;
		*s = '\0';
		d = ++s;
		if (*s && *s != '<') { // tag character content
			while (*s && *s != '<') s++;
			if (*s) ezxml_char_content(root, d, s - d, '&');
			else break;
		}
		else if (! *s) break;
	}

	if (! root->cur) return root;
	else if (! root->cur->name) return ezxml_err((XML::Root *) root, d, "root tag missing");
	else return ezxml_err((XML::Root *) root, d, "unclosed tag <%s>", root->cur->name);
}

// Wrapper for XML::parse_str() that accepts a file stream. Reads the entire
// stream into memory and then parses it. For xml files, use ezxml_parse_file()
// or ezxml_parse_fd()
XML *XML :: parse_fp(FILE *fp)
{
	XML::Root * root;
	size_t l, len = 0;
	char *s;

	if (! (s = (char *) malloc(EZXML_BUFSIZE))) return NULL;
	do {
		len += (l = fread((s + len), 1, EZXML_BUFSIZE, fp));
		if (l == EZXML_BUFSIZE) s = (char *) realloc(s, len + EZXML_BUFSIZE);
	} while (s && l == EZXML_BUFSIZE);

	if (! s) return NULL;
	root = (XML::Root *)XML::parse_str(s, len);
	root->len = -1; // so we know to free s in ezxml_free()
	return root;
}

// A wrapper for XML::parse_str() that accepts a file descriptor. First
// attempts to mem map the file. Failing that, reads the file into memory.
// Returns NULL on failure.
XML *XML :: parse_fd(int fd)
{
	XML::Root * root;
	struct stat st;
	size_t l;
	char *m;

	if (fd < 0) return NULL;
	fstat(fd, &st);

#ifndef EZXML_NOMMAP
	l = (st.st_size + sysconf(_SC_PAGESIZE) - 1) & ~(sysconf(_SC_PAGESIZE) -1);
	if ((m = (char *) mmap(NULL, l, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0)) !=
		MAP_FAILED) {
		madvise(m, l, MADV_SEQUENTIAL); // optimize for sequential access
		root = (XML::Root *)XML::parse_str(m, st.st_size);
		madvise(m, root->len = l, MADV_NORMAL); // put it back to normal
	}
	else { // mmap failed, read file into memory
#endif // EZXML_NOMMAP
		l = read(fd, m = (char *) malloc(st.st_size), st.st_size);
		root = (XML::Root *)XML::parse_str(m, l);
		root->len = -1; // so we know to free s in ezxml_free()
#ifndef EZXML_NOMMAP
	}
#endif // EZXML_NOMMAP
	return root;
}

// a wrapper for ezxml_parse_fd that accepts a file name
XML *XML :: parse_file(const char *path)
{
	int fd = open(path, O_RDONLY, 0);
	XML *xml = XML::parse_fd(fd);
	
	if (fd >= 0) close(fd);
	return xml;
}

// Encodes ampersand sequences appending the results to *dst, reallocating *dst
// if length excedes max. a is non-zero for attribute encoding. Returns *dst
char *ezxml_ampencode(const char *s, size_t len, char **dst, size_t *dlen,
					  size_t *max, short a)
{
	const char *e;
	
	for (e = s + len; s != e; s++) {
		while (*dlen + 10 > *max) *dst = (char *) realloc(*dst, *max += EZXML_BUFSIZE);

		switch (*s) {
		case '\0': return *dst;
		case '&': *dlen += sprintf(*dst + *dlen, "&amp;"); break;
		case '<': *dlen += sprintf(*dst + *dlen, "&lt;"); break;
		case '>': *dlen += sprintf(*dst + *dlen, "&gt;"); break;
		case '"': *dlen += sprintf(*dst + *dlen, (a) ? "&quot;" : "\""); break;
		case '\n': *dlen += sprintf(*dst + *dlen, (a) ? "&#xA;" : "\n"); break;
		case '\t': *dlen += sprintf(*dst + *dlen, (a) ? "&#x9;" : "\t"); break;
		case '\r': *dlen += sprintf(*dst + *dlen, "&#xD;"); break;
		default: (*dst)[(*dlen)++] = *s;
		}
	}
	return *dst;
}

// Recursively converts each tag to xml appending it to *s. Reallocates *s if
// its length excedes max. start is the location of the previous tag in the
// parent tag's character content. Returns *s.
char *ezxml_toxml_r(XML *node, char **s, size_t *len, size_t *max,
					size_t start, char ***attr)
{
	int i, j;
	char *txt = (node->parent) ? node->parent->txt : (char *) "";
	size_t off = 0;

	// parent character content up to this tag
	*s = ezxml_ampencode(txt + start, node->off - start, s, len, max, 0);

	while (*len + strlen(node->name) + 4 > *max) // reallocate s
		*s = (char *) realloc(*s, *max += EZXML_BUFSIZE);

	*len += sprintf(*s + *len, "<%s", node->name); // open tag
	for (i = 0; node->attr[i]; i += 2) { // tag attributes
		if (node->get_attr(node->attr[i]) != node->attr[i + 1]) continue;
		while (*len + strlen(node->attr[i]) + 7 > *max) // reallocate s
			*s = (char *) realloc(*s, *max += EZXML_BUFSIZE);

		*len += sprintf(*s + *len, " %s=\"", node->attr[i]);
		ezxml_ampencode(node->attr[i + 1], -1, s, len, max, 1);
		*len += sprintf(*s + *len, "\"");
	}

	for (i = 0; attr[i] && strcmp(attr[i][0], node->name); i++);
	for (j = 1; attr[i] && attr[i][j]; j += 3) { // default attributes
		if (! attr[i][j + 1] || node->get_attr(attr[i][j]) != attr[i][j + 1])
			continue; // skip duplicates and non-values
		while (*len + strlen(attr[i][j]) + 7 > *max) // reallocate s
			*s = (char *) realloc(*s, *max += EZXML_BUFSIZE);

		*len += sprintf(*s + *len, " %s=\"", attr[i][j]);
		ezxml_ampencode(attr[i][j + 1], -1, s, len, max, 1);
		*len += sprintf(*s + *len, "\"");
	}
	*len += sprintf(*s + *len, ">");

	*s = (node->child) ? ezxml_toxml_r(node->child, s, len, max, 0, attr) //child
					  : ezxml_ampencode(node->txt, -1, s, len, max, 0);  //data
	
	while (*len + strlen(node->name) + 4 > *max) // reallocate s
		*s = (char *) realloc(*s, *max += EZXML_BUFSIZE);

	*len += sprintf(*s + *len, "</%s>", node->name); // close tag

	while (txt[off] && off < node->off) off++; // make sure off is within bounds
	return (node->ordered) ? ezxml_toxml_r(node->ordered, s, len, max, off, attr)
						  : ezxml_ampencode(txt + off, -1, s, len, max, 0);
}

// Converts an ezxml structure back to xml. Returns a string of xml data that
// must be freed.
char *XML :: to_xml(XML *node)
{
	XML *p = (node) ? node->parent : NULL, *o = (node) ? node->ordered : NULL;
	XML::Root * root = (XML::Root *)node;
	size_t len = 0, max = EZXML_BUFSIZE;
	char *s = strcpy((char *) malloc(max), ""), *t, *n;
	int i, j, k;

	if (! node || ! node->name) return (char *) realloc(s, len + 1);
	while (root->parent) root = (XML::Root *)root->parent; // root tag

	for (i = 0; ! p && root->pi[i]; i++) { // pre-root processing instructions
		for (k = 2; root->pi[i][k - 1]; k++);
		for (j = 1; (n = root->pi[i][j]); j++) {
			if (root->pi[i][k][j - 1] == '>') continue; // not pre-root
			while (len + strlen(t = root->pi[i][0]) + strlen(n) + 7 > max)
				s = (char *) realloc(s, max += EZXML_BUFSIZE);
			len += sprintf(s + len, "<?%s%s%s?>\n", t, *n ? " " : "", n);
		}
	}

	node->parent = node->ordered = NULL;
	s = ezxml_toxml_r(node, &s, &len, &max, 0, root->default_attrs);
	node->parent = p;
	node->ordered = o;

	for (i = 0; ! p && root->pi[i]; i++) { // post-root processing instructions
		for (k = 2; root->pi[i][k - 1]; k++);
		for (j = 1; (n = root->pi[i][j]); j++) {
			if (root->pi[i][k][j - 1] == '<') continue; // not post-root
			while (len + strlen(t = root->pi[i][0]) + strlen(n) + 7 > max)
				s = (char *) realloc(s, max += EZXML_BUFSIZE);
			len += sprintf(s + len, "\n<?%s%s%s?>", t, *n ? " " : "", n);
		}
	}
	return (char *) realloc(s, len + 1);
}

// free the memory allocated for the ezxml structure
XML::Root :: ~Root()
{
	int i, j;
	char **a, *s;

	{
		// free this tag allocations
		for (i = 10; this->ent[i]; i += 2) // 0 - 9 are default entites (<>&"')
			if ((s = this->ent[i + 1]) < this->s || s > this->e) free(s);
		free(this->ent); // free list of general entities

		for (i = 0; (a = this->default_attrs[i]); i++) {
			for (j = 1; a[j++]; j += 2) // free malloced attribute values
				if (a[j] && (a[j] < this->s || a[j] > this->e)) free(a[j]);
			free(a);
		}
		if (this->attr[0]) free(this->attr); // free default attribute list

		for (i = 0; this->pi[i]; i++) {
			for (j = 1; this->pi[i][j]; j++);
			free(this->pi[i][j + 1]);
			free(this->pi[i]);
		}            
		if (this->pi[0]) free(this->pi); // free processing instructions

		if (this->len == -1) free(this->m); // malloced xml data
#ifndef EZXML_NOMMAP
		else if (this->len) munmap(this->m, this->len); // mem mapped xml data
#endif // EZXML_NOMMAP
		if (this->u) free(this->u); // utf8 conversion
	}
}

XML :: ~XML()
{
	delete this->child;
	delete this->ordered;

	ezxml_free_attr(this->attr); // tag attributes
	if ((this->flags & EZXML_TXTM)) free(this->txt); // character content
	if ((this->flags & EZXML_NAMEM)) free(this->name); // tag name
}

// return parser error message or empty string if none
const char *XML :: get_error(XML *node)
{
	if (! node) return "";
	
	return XML::get_root(node)->err;
}

// returns a new empty root element with the given root tag name
XML::Root :: Root(const char *name) : XML(name)
{
	static char *ent[] = { "lt;", "&#60;", "gt;", "&#62;", "quot;", "&#34;",
						   "apos;", "&#39;", "amp;", "&#38;", NULL };
	this->cur = this;
	strcpy(this->err, this->txt = "");
	this->ent = (char **) memcpy((char *) malloc(sizeof(ent)), ent, sizeof(ent));
	this->default_attrs = this->pi = (char ***)(this->attr = EZXML_NIL);
}

XML :: XML(const char *name)
{
	this->name = (char *) name;
	this->txt  = "";
	this->attr = EZXML_NIL;
	this->off  = 0;
	
	this->parent  = NULL;
	this->child   = NULL;
	this->next    = NULL;
	this->sibling = NULL;
	this->ordered = NULL;
	
	this->flags = 0;
}

// inserts an existing tag into an ezxml structure
void XML :: insert(XML *node, size_t off)
{
    XML *cur, *prev, *head;

    node->next = node->sibling = node->ordered = NULL;
    node->off = off;
    node->parent = this;

    if ((head = this->child)) { // already have sub tags
        if (head->off <= off) { // not first subtag
            for (cur = head; cur->ordered && cur->ordered->off <= off;
                 cur = cur->ordered);
            node->ordered = cur->ordered;
            cur->ordered = node;
        }
        else { // first subtag
            node->ordered = head;
            this->child = node;
        }

        for (cur = head, prev = NULL; cur && strcmp(cur->name, node->name);
             prev = cur, cur = cur->sibling); // find tag type
        if (cur && cur->off <= off) { // not first of type
            while (cur->next && cur->next->off <= off) cur = cur->next;
            node->next = cur->next;
            cur->next = node;
        }
        else { // first tag of this type
            if (prev && cur) prev->sibling = cur->sibling; // remove old first
            node->next = cur; // old first tag is now next
            for (cur = head, prev = NULL; cur && cur->off <= off;
                 prev = cur, cur = cur->sibling); // new sibling insert point
            node->sibling = cur;
            if (prev) prev->sibling = node;
        }
    }
    else this->child = node; // only sub tag
}

XML *XML :: add_child(const char *name, size_t off)
{
	/* Adds a child tag. off is the offset of the child tag relative to the start	*
	 * of the parent tag's character content. Returns the child tag.				*/

	XML *child = new XML(name);
	
	this->insert(child, off);
	
	return child;
}

// sets the character content for the given tag and returns the tag
void XML :: set_text(const char *txt, bool copy)
{
	if (this->flags & EZXML_TXTM)
	{
		/* Free existing text if it was malloced */
		free(this->txt);
	}

	if (copy)
	{
		this->txt = strdup(txt);
	}
	else
	{
		this->flags &= ~EZXML_TXTM;
		this->txt = (char *)txt;
	}
}

// Sets the given tag attribute or adds a new attribute if not found. A value
// of NULL will remove the specified attribute. Returns the tag given.
void XML :: set_attr(const char *name, const char *value)
{
	int l = 0, c;

	while (this->attr[l] && strcmp(this->attr[l], name)) l += 2;
	if (! this->attr[l]) { // not found, add as new attribute
		if (! value) return; // nothing to do
		if (this->attr == EZXML_NIL) { // first attribute
			this->attr = (char **) malloc(4 * sizeof(char *));
			this->attr[1] = strdup(""); // empty list of malloced names/vals
		}
		else this->attr = (char **) realloc(this->attr, (l + 4) * sizeof(char *));

		this->attr[l] = (char *)name; // set attribute name
		this->attr[l + 2] = NULL; // null terminate attribute list
		this->attr[l + 3] = (char *) realloc(this->attr[l + 1],
								   (c = strlen(this->attr[l + 1])) + 2);
		strcpy(this->attr[l + 3] + c, " "); // set name/value as not malloced
		if (this->flags & EZXML_DUP) this->attr[l + 3][c] = EZXML_NAMEM;
	}
	else if (this->flags & EZXML_DUP) free((char *)name); // name was strduped

	for (c = l; this->attr[c]; c += 2); // find end of attribute list
	if (this->attr[c + 1][l / 2] & EZXML_TXTM) free(this->attr[l + 1]); //old val
	if (this->flags & EZXML_DUP) this->attr[c + 1][l / 2] |= EZXML_TXTM;
	else this->attr[c + 1][l / 2] &= ~EZXML_TXTM;

	if (value) this->attr[l + 1] = (char *)value; // set attribute value
	else { // remove attribute
		if (this->attr[c + 1][l / 2] & EZXML_NAMEM) free(this->attr[l]);
		memmove(this->attr + l, this->attr + l + 2, (c - l + 2) * sizeof(char*));
		this->attr = (char **) realloc(this->attr, (c + 2) * sizeof(char *));
		memmove(this->attr[c + 1] + (l / 2), this->attr[c + 1] + (l / 2) + 1,
				(c / 2) - (l / 2)); // fix list of which name/vals are malloced
	}
	this->flags &= ~EZXML_DUP; // clear strdup() flag
}

// removes a tag along with its subtags without freeing its memory
XML *XML :: cut(XML *node)
{
	XML *cur;

	if (! node) return NULL; // nothing to do
	if (node->next) node->next->sibling = node->sibling; // patch sibling list

	if (node->parent) { // not root tag
		cur = node->parent->child; // find head of subtag list
		if (cur == node) node->parent->child = node->ordered; // first subtag
		else { // not first subtag
			while (cur->ordered != node) cur = cur->ordered;
			cur->ordered = cur->ordered->ordered; // patch ordered list

			cur = node->parent->child; // go back to head of subtag list
			if (strcmp(cur->name, node->name)) { // not in first sibling list
				while (strcmp(cur->sibling->name, node->name))
					cur = cur->sibling;
				if (cur->sibling == node) { // first of a sibling list
					cur->sibling = (node->next) ? node->next
											   : cur->sibling->sibling;
				}
				else cur = cur->sibling; // not first of a sibling list
			}

			while (cur->next && cur->next != node) cur = cur->next;
			if (cur->next) cur->next = cur->next->next; // patch next list
		}        
	}
	node->ordered = node->sibling = node->next = NULL;
	return node;
}

#ifdef EZXML_TEST // test harness
int main(int argc, char **argv)
{
	XML *xml;
	char *s;
	int i;

	if (argc != 2) return fprintf(stderr, "usage: %s xmlfile\n", argv[0]);

	xml = XML::parse_file(argv[1]);
	printf("%s\n", (s = XML::to_xml(xml)));
	free(s);
	i = fprintf(stderr, "%s", XML::get_error(xml));
	delete xml;
	return (i) ? 1 : 0;
}
#endif // EZXML_TEST
