/*
 * commoncrypto.c - CommonCrypto bindings for Python
 * Copyright (c) 2008-2011 Ruda Moura <ruda.moura@gmail.com>
 */

#include <Python.h>
#include <CommonCrypto/CommonDigest.h>

/* MD2, MD4, MD5 hash functions */

static PyObject *
MD2_Init(PyObject * self, PyObject * args)
{
	CC_MD2_CTX *c = malloc(sizeof(CC_MD2_CTX));
	if (!c)
		return PyErr_NoMemory();
	CC_MD2_Init(c);
	PyObject *o = PyInt_FromLong((long) c);
	return o;
}

static PyObject *
MD2_Update(PyObject * self, PyObject * args)
{
	long c;
	const void *data;
	long size;
	if (!PyArg_ParseTuple(args, "ls#", &c, &data, &size))
		return NULL;
	CC_MD2_Update((CC_MD2_CTX *) c, data, size);
	Py_RETURN_NONE;
}

static PyObject *
MD2_Final(PyObject * self, PyObject * args)
{
	long c;
	unsigned char *md;
	if (!PyArg_ParseTuple(args, "l", &c))
		return NULL;
	md = malloc(CC_MD2_DIGEST_LENGTH);
	if (!md)
		return PyErr_NoMemory();
	CC_MD2_Final(md, (CC_MD2_CTX *) c);
	PyObject *o = PyString_FromStringAndSize((char *) md, CC_MD2_DIGEST_LENGTH);
	free(md);
	free((CC_MD2_CTX *) c);
	return o;
}

static PyObject *
MD2(PyObject * self, PyObject * args)
{
	unsigned char *md;
	const void *data;
	long size;
	if (!PyArg_ParseTuple(args, "s#", &data, &size))
		return NULL;
	md = malloc(CC_MD2_DIGEST_LENGTH);
	CC_MD2(data, size, md);
	PyObject *o = PyString_FromStringAndSize((char *) md, CC_MD2_DIGEST_LENGTH);
	free(md);
	return o;
}

static PyObject *
MD4_Init(PyObject * self, PyObject * args)
{
	CC_MD4_CTX *c = malloc(sizeof(CC_MD4_CTX));
	if (!c)
		return PyErr_NoMemory();
	CC_MD4_Init(c);
	PyObject *o = PyInt_FromLong((long) c);
	return o;
}

static PyObject *
MD4_Update(PyObject * self, PyObject * args)
{
	long c;
	const void *data;
	long size;
	if (!PyArg_ParseTuple(args, "ls#", &c, &data, &size))
		return NULL;
	CC_MD4_Update((CC_MD4_CTX *) c, data, size);
	Py_RETURN_NONE;
}

static PyObject *
MD4_Final(PyObject * self, PyObject * args)
{
	long c;
	unsigned char *md;
	if (!PyArg_ParseTuple(args, "l", &c))
		return NULL;
	md = malloc(CC_MD4_DIGEST_LENGTH);
	if (!md)
		return PyErr_NoMemory();
	CC_MD4_Final(md, (CC_MD4_CTX *) c);
	PyObject *o = PyString_FromStringAndSize((char *) md, CC_MD4_DIGEST_LENGTH);
	free(md);
	free((CC_MD4_CTX *) c);
	return o;
}

static PyObject *
MD4(PyObject * self, PyObject * args)
{
	unsigned char *md;
	const void *data;
	long size;
	if (!PyArg_ParseTuple(args, "s#", &data, &size))
		return NULL;
	md = malloc(CC_MD4_DIGEST_LENGTH);
	CC_MD4(data, size, md);
	PyObject *o = PyString_FromStringAndSize((char *) md, CC_MD4_DIGEST_LENGTH);
	free(md);
	return o;
}

static PyObject *
MD5_Init(PyObject * self, PyObject * args)
{
	CC_MD5_CTX *c = malloc(sizeof(CC_MD5_CTX));
	if (!c)
		return PyErr_NoMemory();
	CC_MD5_Init(c);
	PyObject *o = PyInt_FromLong((long) c);
	return o;
}

static PyObject *
MD5_Update(PyObject * self, PyObject * args)
{
	long c;
	const char *data;
	long size;
	if (!PyArg_ParseTuple(args, "ls#", &c, &data, &size))
		return NULL;
	CC_MD5_Update((CC_MD5_CTX *) c, data, size);
	Py_RETURN_NONE;
}

static PyObject *
MD5_Final(PyObject * self, PyObject * args)
{
	long c;
	unsigned char *md;
	if (!PyArg_ParseTuple(args, "l", &c))
		return NULL;
	md = malloc(CC_MD5_DIGEST_LENGTH);
	if (!md)
		return PyErr_NoMemory();
	CC_MD5_Final(md, (CC_MD5_CTX *) c);
	PyObject *o = PyString_FromStringAndSize((char *) md, CC_MD5_DIGEST_LENGTH);
	free(md);
	free((CC_MD5_CTX *) c);
	return o;
}

static PyObject *
MD5(PyObject * self, PyObject * args)
{
	unsigned char *md;
	const void *data;
	long size;
	if (!PyArg_ParseTuple(args, "s#", &data, &size))
		return NULL;
	md = malloc(CC_MD5_DIGEST_LENGTH);
	CC_MD5(data, size, md);
	PyObject *o = PyString_FromStringAndSize((char *) md, CC_MD5_DIGEST_LENGTH);
	free(md);
	return o;
}

/* Secure Hash Algorithms */

static PyObject *
SHA1_Init(PyObject * self, PyObject * args)
{
	CC_SHA1_CTX *c = malloc(sizeof(CC_SHA1_CTX));
	if (!c)
		return PyErr_NoMemory();
	CC_SHA1_Init(c);
	PyObject *o = PyInt_FromLong((long) c);
	return o;
}

static PyObject *
SHA1_Update(PyObject * self, PyObject * args)
{
	long c;
	const void *data;
	long size;
	if (!PyArg_ParseTuple(args, "ls#", &c, &data, &size))
		return NULL;
	CC_SHA1_Update((CC_SHA1_CTX *) c, data, size);
	Py_RETURN_NONE;
}

static PyObject *
SHA1_Final(PyObject * self, PyObject * args)
{
	long c;
	unsigned char *md;
	if (!PyArg_ParseTuple(args, "l", &c))
		return NULL;
	md = malloc(CC_SHA1_DIGEST_LENGTH);
	if (!md)
		return PyErr_NoMemory();
	CC_SHA1_Final(md, (CC_SHA1_CTX *) c);
	PyObject *o = PyString_FromStringAndSize((char *) md, CC_SHA1_DIGEST_LENGTH);
	free(md);
	free((CC_SHA1_CTX *) c);
	return o;
}

static PyObject *
SHA1(PyObject * self, PyObject * args)
{
	unsigned char *md;
	const void *data;
	long size;
	if (!PyArg_ParseTuple(args, "s#", &data, &size))
		return NULL;
	md = malloc(CC_SHA1_DIGEST_LENGTH);
	CC_SHA1(data, size, md);
	PyObject *o = PyString_FromStringAndSize((char *) md, CC_SHA1_DIGEST_LENGTH);
	free(md);
	return o;
}

static PyObject *
SHA224_Init(PyObject * self, PyObject * args)
{
	CC_SHA256_CTX *c = malloc(sizeof(CC_SHA256_CTX));
	if (!c)
		return PyErr_NoMemory();
	CC_SHA224_Init(c);
	PyObject *o = PyInt_FromLong((long) c);
	return o;
}

/* NOTE: Documentation is wrong! There is no CC_SHA224_CTX */
static PyObject *
SHA224_Update(PyObject * self, PyObject * args)
{
	long c;
	const void *data;
	long size;
	if (!PyArg_ParseTuple(args, "ls#", &c, &data, &size))
		return NULL;
	CC_SHA224_Update((CC_SHA256_CTX *) c, data, size);
	Py_RETURN_NONE;
}

static PyObject *
SHA224_Final(PyObject * self, PyObject * args)
{
	long c;
	unsigned char *md;
	if (!PyArg_ParseTuple(args, "l", &c))
		return NULL;
	md = malloc(CC_SHA224_DIGEST_LENGTH);
	if (!md)
		return PyErr_NoMemory();
	CC_SHA224_Final(md, (CC_SHA256_CTX *) c);
	PyObject *o = PyString_FromStringAndSize((char *) md, CC_SHA224_DIGEST_LENGTH);
	free(md);
	free((CC_SHA256_CTX *) c);
	return o;
}

static PyObject *
SHA224(PyObject * self, PyObject * args)
{
	unsigned char *md;
	const void *data;
	long size;
	if (!PyArg_ParseTuple(args, "s#", &data, &size))
		return NULL;
	md = malloc(CC_SHA224_DIGEST_LENGTH);
	CC_SHA224(data, size, md);
	PyObject *o = PyString_FromStringAndSize((char *) md, CC_SHA224_DIGEST_LENGTH);
	free(md);
	return o;
}

static PyObject *
SHA256_Init(PyObject * self, PyObject * args)
{
	CC_SHA256_CTX *c = malloc(sizeof(CC_SHA256_CTX));
	if (!c)
		return PyErr_NoMemory();
	CC_SHA256_Init(c);
	PyObject *o = PyInt_FromLong((long) c);
	return o;
}

static PyObject *
SHA256_Update(PyObject * self, PyObject * args)
{
	long c;
	const void *data;
	long size;
	if (!PyArg_ParseTuple(args, "ls#", &c, &data, &size))
		return NULL;
	CC_SHA256_Update((CC_SHA256_CTX *) c, data, size);
	Py_RETURN_NONE;
}

static PyObject *
SHA256_Final(PyObject * self, PyObject * args)
{
	long c;
	unsigned char *md;
	if (!PyArg_ParseTuple(args, "l", &c))
		return NULL;
	md = malloc(CC_SHA256_DIGEST_LENGTH);
	if (!md)
		return PyErr_NoMemory();
	CC_SHA256_Final(md, (CC_SHA256_CTX *) c);
	PyObject *o = PyString_FromStringAndSize((char *) md, CC_SHA256_DIGEST_LENGTH);
	free(md);
	free((CC_SHA256_CTX *) c);
	return o;
}

static PyObject *
SHA256(PyObject * self, PyObject * args)
{
	unsigned char *md;
	const void *data;
	long size;
	if (!PyArg_ParseTuple(args, "s#", &data, &size))
		return NULL;
	md = malloc(CC_SHA256_DIGEST_LENGTH);
	CC_SHA256(data, size, md);
	PyObject *o = PyString_FromStringAndSize((char *) md, CC_SHA256_DIGEST_LENGTH);
	free(md);
	return o;
}

static PyObject *
SHA384_Init(PyObject * self, PyObject * args)
{
	CC_SHA512_CTX *c = malloc(sizeof(CC_SHA512_CTX));
	if (!c)
		return PyErr_NoMemory();
	CC_SHA384_Init(c);
	PyObject *o = PyInt_FromLong((long) c);
	return o;
}

static PyObject *
SHA384_Update(PyObject * self, PyObject * args)
{
	long c;
	const void *data;
	long size;
	if (!PyArg_ParseTuple(args, "ls#", &c, &data, &size))
		return NULL;
	CC_SHA384_Update((CC_SHA512_CTX *) c, data, size);
	Py_RETURN_NONE;
}

static PyObject *
SHA384_Final(PyObject * self, PyObject * args)
{
	long c;
	unsigned char *md;
	if (!PyArg_ParseTuple(args, "l", &c))
		return NULL;
	md = malloc(CC_SHA384_DIGEST_LENGTH);
	if (!md)
		return PyErr_NoMemory();
	CC_SHA384_Final(md, (CC_SHA512_CTX *) c);
	PyObject *o = PyString_FromStringAndSize((char *) md, CC_SHA384_DIGEST_LENGTH);
	free(md);
	free((CC_SHA512_CTX *) c);
	return o;
}

static PyObject *
SHA384(PyObject * self, PyObject * args)
{
	unsigned char *md;
	const void *data;
	long size;
	if (!PyArg_ParseTuple(args, "s#", &data, &size))
		return NULL;
	md = malloc(CC_SHA384_DIGEST_LENGTH);
	CC_SHA384(data, size, md);
	PyObject *o = PyString_FromStringAndSize((char *) md, CC_SHA384_DIGEST_LENGTH);
	free(md);
	return o;
}

static PyObject *
SHA512_Init(PyObject * self, PyObject * args)
{
	CC_SHA512_CTX *c = malloc(sizeof(CC_SHA512_CTX));
	if (!c)
		return PyErr_NoMemory();
	CC_SHA512_Init(c);
	PyObject *ctx = PyInt_FromLong((long) c);
	return ctx;
}

static PyObject *
SHA512_Update(PyObject * self, PyObject * args)
{
	long c;
	const void *data;
	long size;
	if (!PyArg_ParseTuple(args, "ls#", &c, &data, &size))
		return NULL;
	CC_SHA512_Update((CC_SHA512_CTX *) c, data, size);
	Py_RETURN_NONE;
}

static PyObject *
SHA512_Final(PyObject * self, PyObject * args)
{
	long c;
	unsigned char *md;
	if (!PyArg_ParseTuple(args, "l", &c))
		return NULL;
	md = malloc(CC_SHA512_DIGEST_LENGTH);
	if (!md)
		return PyErr_NoMemory();
	CC_SHA512_Final(md, (CC_SHA512_CTX *) c);
	PyObject *o = PyString_FromStringAndSize((char *) md, CC_SHA512_DIGEST_LENGTH);
	free(md);
	free((CC_SHA512_CTX *) c);
	return o;
}

static PyObject *
SHA512(PyObject * self, PyObject * args)
{
	unsigned char *md;
	const void *data;
	long size;
	if (!PyArg_ParseTuple(args, "s#", &data, &size))
		return NULL;
	md = malloc(CC_SHA512_DIGEST_LENGTH);
	CC_SHA512(data, size, md);
	PyObject *o = PyString_FromStringAndSize((char *) md, CC_SHA512_DIGEST_LENGTH);
	free(md);
	return o;
}

PyMethodDef methods[] = {
	{"MD2_Init", MD2_Init, METH_VARARGS, "Initializes a MD2 context"},
	{"MD2_Update", MD2_Update, METH_VARARGS, "Updates chunks of the message to be hashed"},
	{"MD2_Final", MD2_Final, METH_VARARGS, "Returns the MD2 message digest"},
	{"MD2", MD2, METH_VARARGS, "Computes the MD2 message digest"},
	{"MD4_Init", MD4_Init, METH_VARARGS, "Initializes a MD4 context"},
	{"MD4_Update", MD4_Update, METH_VARARGS, "Updates chunks of the message to be hashed"},
	{"MD4_Final", MD4_Final, METH_VARARGS, "Returns the MD4 message digest"},
	{"MD4", MD4, METH_VARARGS, "Computes the MD4 message digest"},
	{"MD5_Init", MD5_Init, METH_VARARGS, "Initializes a MD5 context"},
	{"MD5_Update", MD5_Update, METH_VARARGS, "Updates chunks of the message to be hashed"},
	{"MD5_Final", MD5_Final, METH_VARARGS, "Returns the MD5 message digest"},
	{"MD5", MD5, METH_VARARGS, "Computes the MD5 message digest"},
	{"SHA1_Init", SHA1_Init, METH_VARARGS, "Initializes a SHA1 context"},
	{"SHA1_Update", SHA1_Update, METH_VARARGS, "Updates chunks of the message to be hashed"},
	{"SHA1_Final", SHA1_Final, METH_VARARGS, "Returns the SHA1 message digest"},
	{"SHA1", SHA1, METH_VARARGS, "Computes the SHA-1 message digest"},
	{"SHA224_Init", SHA224_Init, METH_VARARGS, "Initializes a SHA224 context"},
	{"SHA224_Update", SHA224_Update, METH_VARARGS, "Updates chunks of the message to be hashed"},
	{"SHA224_Final", SHA224_Final, METH_VARARGS, "Returns the SHA224 message digest"},
	{"SHA224", SHA224, METH_VARARGS, "Computes the SHA-224 message digest"},
	{"SHA256_Init", SHA256_Init, METH_VARARGS, "Initializes a SHA256 context"},
	{"SHA256_Update", SHA256_Update, METH_VARARGS, "Updates chunks of the message to be hashed"},
	{"SHA256_Final", SHA256_Final, METH_VARARGS, "Returns the SHA256 message digest"},
	{"SHA256", SHA256, METH_VARARGS, "Computes the SHA-256 message digest"},
	{"SHA384_Init", SHA384_Init, METH_VARARGS, "Initializes a SHA384 context"},
	{"SHA384_Update", SHA384_Update, METH_VARARGS, "Updates chunks of the message to be hashed"},
	{"SHA384_Final", SHA384_Final, METH_VARARGS, "Returns the SHA384 message digest"},
	{"SHA384", SHA384, METH_VARARGS, "Computes the SHA-384 message digest"},
	{"SHA512_Init", SHA512_Init, METH_VARARGS, "Initializes a SHA512 context"},
	{"SHA512_Update", SHA512_Update, METH_VARARGS, "Updates chunks of the message to be hashed"},
	{"SHA512_Final", SHA512_Final, METH_VARARGS, "Returns the SHA512 message digest"},
	{"SHA512", SHA512, METH_VARARGS, "Computes the SHA-512 message digest"},
	{NULL, NULL, 0, NULL}
};

PyMODINIT_FUNC
init_commoncrypto()
{
	(void) Py_InitModule3("_commoncrypto", methods,
			      "Python bindings for Common Crypto library");
}
