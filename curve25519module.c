/* tell python that PyArg_ParseTuple(t#) means Py_ssize_t, not int */
#define PY_SSIZE_T_CLEAN
#include <Python.h>
#if (PY_VERSION_HEX < 0x02050000)
	typedef int Py_ssize_t;
#endif

/* This is required for compatibility with Python 2. */
#if PY_MAJOR_VERSION >= 3
	#include <bytesobject.h>
	#define y "y"
#else
	#define PyBytes_FromStringAndSize PyString_FromStringAndSize
	#define y "t"
#endif

int curve25519_sign(unsigned char* signature_out,
                    const unsigned char* curve25519_privkey,
                    const unsigned char* msg, const unsigned long msg_len,
                    const unsigned char* random);

int curve25519_verify(const unsigned char* signature,
                      const unsigned char* curve25519_pubkey,
                      const unsigned char* msg, const unsigned long msg_len);


int curve25519_donna(char *mypublic,
                     const char *secret, const char *basepoint);

static PyObject *
calculateSignature(PyObject *self, PyObject *args)
{
    const char *random;
    const char *privatekey;
    const char *message;
    char signature[64];
    Py_ssize_t randomlen, privatekeylen, messagelen;

    if (!PyArg_ParseTuple(args, y"#"y"#"y"#:generate",&random, &randomlen, &privatekey, &privatekeylen, &message, &messagelen))
        return NULL;
     if (privatekeylen != 32) {
        PyErr_SetString(PyExc_ValueError, "private key must be 32-byte string" );
        return NULL;
    }
    if (randomlen != 64) {
        PyErr_SetString(PyExc_ValueError, "random must be 64-byte string");
        return NULL;
    }

    curve25519_sign((unsigned char *)signature, (unsigned char *)privatekey, 
                    (unsigned char *)message, messagelen, (unsigned char *)random);

   return PyBytes_FromStringAndSize((char *)signature, 64);
}

static PyObject *
verifySignature(PyObject *self, PyObject *args)
{
    const char *publickey;
    const char *message;
    const char *signature;

    Py_ssize_t publickeylen, messagelen, signaturelen;

    if (!PyArg_ParseTuple(args, y"#"y"#"y"#:generate", &publickey, &publickeylen, &message, &messagelen, &signature, &signaturelen))
        return NULL;

     if (publickeylen != 32) {
        PyErr_SetString(PyExc_ValueError, "publickey must be 32-byte string");
        return NULL;
    }
    if (signaturelen != 64) {
        PyErr_SetString(PyExc_ValueError, "signature must be 64-byte string");
        return NULL;
    }

    int result = curve25519_verify((unsigned char *)signature, (unsigned char *)publickey, 
                                   (unsigned char *)message, messagelen);

    return Py_BuildValue("i", result);

}

static PyObject *
generatePrivateKey(PyObject *self, PyObject *args)
{
    char *random;
    Py_ssize_t randomlen;

    if(!PyArg_ParseTuple(args, y"#:clamp", &random, &randomlen)) {
        return NULL;
    }

    if(randomlen != 32) {
        PyErr_SetString(PyExc_ValueError, "random must be 32-byte string");
        return NULL;
    }
    random[0] &= 248;
    random[31] &= 127;
    random[31] |= 64;

    return PyBytes_FromStringAndSize((char *)random, 32);
}

static PyObject *
generatePublicKey(PyObject *self, PyObject *args)
{
    const char *private;
    char mypublic[32];
    char basepoint[32] = {9};
    Py_ssize_t privatelen;
    if (!PyArg_ParseTuple(args, y"#:makepublic", &private, &privatelen))
        return NULL;
    if (privatelen != 32) {
        PyErr_SetString(PyExc_ValueError, "input must be 32-byte string");
        return NULL;
    }
    curve25519_donna(mypublic, private, basepoint);
    return PyBytes_FromStringAndSize((char *)mypublic, 32);
}

static PyObject *
calculateAgreement(PyObject *self, PyObject *args)
{
    const char *myprivate, *theirpublic;
    char shared_key[32];
    Py_ssize_t myprivatelen, theirpubliclen;
    if (!PyArg_ParseTuple(args, y"#"y"#:generate",
                          &myprivate, &myprivatelen, &theirpublic, &theirpubliclen))
        return NULL;
    if (myprivatelen != 32) {
        PyErr_SetString(PyExc_ValueError, "input must be 32-byte string");
        return NULL;
    }
    if (theirpubliclen != 32) {
        PyErr_SetString(PyExc_ValueError, "input must be 32-byte string");
        return NULL;
    }
    curve25519_donna(shared_key, myprivate, theirpublic);
    return PyBytes_FromStringAndSize((char *)shared_key, 32);
}


static PyMethodDef
curve25519_functions[] = {
    {"calculateSignature", calculateSignature, METH_VARARGS, "random+privatekey+message->signature"},
    {"verifySignature", verifySignature, METH_VARARGS, "publickey+message+signature->valid"},
    {"generatePrivateKey", generatePrivateKey, METH_VARARGS, "data->private"},
    {"generatePublicKey", generatePublicKey, METH_VARARGS, "private->public"},
    {"calculateAgreement", calculateAgreement, METH_VARARGS, "private+public->shared"},
    {NULL, NULL, 0, NULL},
};


#if PY_MAJOR_VERSION >= 3
    static struct PyModuleDef
    curve25519_module = {
        PyModuleDef_HEAD_INIT,
        "axolotl_curve25519",
        NULL,
        NULL,
        curve25519_functions,
    };

    PyObject *
    PyInit_axolotl_curve25519(void)
    {
        return PyModule_Create(&curve25519_module);
    }
#else

    PyMODINIT_FUNC
    initaxolotl_curve25519(void)
    {
        (void)Py_InitModule("axolotl_curve25519", curve25519_functions);
    }

#endif
