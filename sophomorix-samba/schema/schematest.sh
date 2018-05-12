#!/bin/sh


# file 1_....
echo "Attributes (sorted):"
grep lDAPDisplayName -r ./1_sophomorix-attributes.ldif | sort
grep lDAPDisplayName -r ./1_sophomorix-attributes.ldif | sort | wc -l ;
echo " ... Attributes"

echo "Duplicate lines for lDAPDisplayName (no output means: no error):"
grep lDAPDisplayName -r ./1_sophomorix-attributes.ldif |sort | uniq -D

echo "Duplicate lines for schemaIDGUID (no output means: no error):"
grep schemaIDGUID -r ./1_sophomorix-attributes.ldif |sort | uniq -D

echo "Duplicate lines for attributeID (no output means: no error):"
grep attributeID -r ./1_sophomorix-attributes.ldif |sort | uniq -D


# file 2_....
echo "Duplicate lines for governsID (no output means: no error):"
grep governsID -r ./2_sophomorix-classes.ldif |sort | uniq -D

echo "Duplicate lines for schemaIDGUID (no output means: no error):"
grep schemaIDGUID -r ./2_sophomorix-classes.ldif |sort | uniq -D
