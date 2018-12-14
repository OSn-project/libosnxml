#ifndef __XMLPARSE_H__
#define __XMLPARSE_H__

#include <osndef.h>
#include <stdio.h>

class XML
{
public:
	char  *name;	// Tag name
	char **attr;	// Tag attributes { name, value, name, value, ... NULL }
	char  *txt;		// Tag character content, empty string if none
	size_t off;		// Tag offset from start of parent tag character content

	XML *next;		// Next tag with same name in this section at this depth
	XML *sibling;	// Next tag with different name in same section and depth
	XML *ordered;	// Next tag, same section and depth, in original order

	XML *parent;	// Parent tag, NULL if current tag is root tag
	XML *child;		// Head of sub tag list, NULL if none

	uint16 flags;	// Additional information

public:
	struct Root;
	
public:
	
	XML(const char *name);
	~XML();
	
	const char *get_attr(const char *name);
	const char *get_node_attr(const char *name);
	static const char *get_default_attr(XML::Root *root, const char *tag, const char *attr);
	void        set_attr(const char *name, const char *value);
	
	XML *add_child(const char *name, size_t offset);
	XML *get_child(const char *name);
	void set_text(const char *txt, bool copy=false);
	
	/* Tree manipulation */
	
	static XML *cut(XML *node);
	void        insert(XML *node, size_t offset);
	inline void move(XML *node, XML *dest, size_t offset);
	
	static XML *get(XML *node, ...);
	static Root *get_root(XML *node);
	
	/* Parser */
	static XML *parse_str(char *s, size_t len);
	static XML *parse_fd(int fd);
	static XML *parse_file(const char *path);
	static XML *parse_fp(FILE *fp);
	
	static char *to_xml(XML *node);
	
	/* Misc. */

	static bool parse_bool(const char *attr_text, bool *result);	// Parses the "true"/"false" string into the given . Note that the return value is used to signify an error and is NOT THE PARSED RESULT!
	static const char *get_error(XML *node);		// Get parser error
};

inline void XML :: move(XML *node, XML *dest, size_t offset)
{
	XML::cut(node);
	dest->insert(node, offset);
}

#endif
