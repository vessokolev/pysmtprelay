/*
 * Python C Extension for OCSP Stapling
 * 
 * Based on Exim's OCSP stapling implementation in tls-openssl.c
 * This extension provides access to OpenSSL's OCSP stapling functions
 * that are not exposed by Python's ssl module.
 * 
 * Key functions:
 * - SSL_CTX_set_tlsext_status_cb() - Set callback for OCSP stapling
 * - SSL_CTX_set_tlsext_status_arg() - Set callback argument
 * - SSL_set_tlsext_status_ocsp_resp() - Provide OCSP response
 */

#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <openssl/ssl.h>
#include <openssl/ocsp.h>
#include <openssl/err.h>
#include <structmember.h>

/* Module state structure */
typedef struct {
    PyObject *ocsp_response_cache;  /* Dictionary: cert_hash -> (response_bytes, timestamp) */
} module_state;

/* Get module state */
static inline module_state* get_module_state(PyObject *module) {
    return (module_state*)PyModule_GetState(module);
}

/* OCSP stapling callback function (similar to Exim's tls_server_stapling_cb) */
static int ocsp_stapling_callback(SSL *ssl, void *arg) {
    PyObject *ocsp_response_obj = (PyObject *)arg;
    
    if (!ocsp_response_obj || ocsp_response_obj == Py_None) {
        return SSL_TLSEXT_ERR_NOACK;
    }
    
    /* Get OCSP response bytes from Python object */
    PyObject *response_bytes = NULL;
    if (PyBytes_Check(ocsp_response_obj)) {
        response_bytes = ocsp_response_obj;
        Py_INCREF(response_bytes);
    } else {
        /* Try to convert to bytes */
        response_bytes = PyObject_Bytes(ocsp_response_obj);
        if (!response_bytes) {
            return SSL_TLSEXT_ERR_NOACK;
        }
    }
    
    /* Get DER-encoded OCSP response */
    unsigned char *response_der = (unsigned char *)PyBytes_AsString(response_bytes);
    Py_ssize_t response_len = PyBytes_Size(response_bytes);
    
    if (!response_der || response_len <= 0) {
        Py_DECREF(response_bytes);
        return SSL_TLSEXT_ERR_NOACK;
    }
    
    /* Set OCSP response in TLS handshake */
    int result = SSL_set_tlsext_status_ocsp_resp(ssl, response_der, (int)response_len);
    
    Py_DECREF(response_bytes);
    
    if (result == 0) {
        return SSL_TLSEXT_ERR_NOACK;
    }
    
    return SSL_TLSEXT_ERR_OK;
}

/* Python function: enable_ocsp_stapling(context, ocsp_response_bytes) */
static PyObject *py_enable_ocsp_stapling(PyObject *self, PyObject *args) {
    PyObject *ssl_context_obj;
    PyObject *ocsp_response_obj;
    
    if (!PyArg_ParseTuple(args, "OO", &ssl_context_obj, &ocsp_response_obj)) {
        return NULL;
    }
    
    /* Get underlying SSL_CTX from Python's ssl.SSLContext
     * This is the tricky part - we need to access the internal _context attribute
     * Python's ssl.SSLContext wraps OpenSSL's SSL_CTX, but doesn't expose it directly
     */
    SSL_CTX *ssl_ctx = NULL;
    
    /* Try to get _context attribute (internal, may not be available in all Python versions) */
    PyObject *context_attr = PyObject_GetAttrString(ssl_context_obj, "_context");
    if (context_attr) {
        /* _context is a PyCapsule or similar - we need to extract the SSL_CTX pointer */
        /* This is implementation-dependent and may require different approaches */
        /* For now, we'll use ctypes approach or pyOpenSSL */
        Py_DECREF(context_attr);
    }
    
    /* Alternative: Use ctypes to access SSL_CTX
     * This requires knowing the internal structure of ssl.SSLContext
     * which varies by Python version
     */
    
    /* For now, return an error indicating we need a different approach */
    PyErr_SetString(PyExc_NotImplementedError,
                    "Direct SSL_CTX access not available. "
                    "Use pyOpenSSL contexts or wait for Python native support.");
    return NULL;
}

/* Python function: get_ssl_ctx_from_context(ssl_context) - Returns SSL_CTX pointer as integer */
static PyObject *py_get_ssl_ctx_from_context(PyObject *self, PyObject *args) {
    PyObject *ssl_context_obj;
    
    if (!PyArg_ParseTuple(args, "O", &ssl_context_obj)) {
        return NULL;
    }
    
    SSL_CTX *ssl_ctx = NULL;
    
    /* Try multiple methods to extract SSL_CTX pointer */
    
    /* Method 1: Direct _context attribute access */
    PyObject *context_attr = PyObject_GetAttrString(ssl_context_obj, "_context");
    if (context_attr) {
        /* Try as PyCapsule */
        if (PyCapsule_CheckExact(context_attr)) {
            ssl_ctx = (SSL_CTX *)PyCapsule_GetPointer(context_attr, NULL);
        }
        /* Try as integer (ctypes pointer) */
        else if (PyLong_Check(context_attr)) {
            ssl_ctx = (SSL_CTX *)PyLong_AsVoidPtr(context_attr);
        }
        Py_DECREF(context_attr);
    }
    
    if (!ssl_ctx) {
        PyErr_SetString(PyExc_ValueError,
                        "Could not extract SSL_CTX pointer from ssl.SSLContext. "
                        "This may require a different approach for your Python version.");
        return NULL;
    }
    
    /* Return SSL_CTX pointer as Python integer (for ctypes) */
    return PyLong_FromVoidPtr(ssl_ctx);
}

/* Python function: set_ocsp_response_callback(ssl_ctx_ptr, ocsp_response_bytes) */
static PyObject *py_set_ocsp_response_callback(PyObject *self, PyObject *args) {
    PyObject *ssl_ctx_ptr_obj;
    PyObject *ocsp_response_obj;
    
    if (!PyArg_ParseTuple(args, "OO", &ssl_ctx_ptr_obj, &ocsp_response_obj)) {
        return NULL;
    }
    
    /* Get SSL_CTX pointer (passed as integer/pointer from ctypes) */
    SSL_CTX *ssl_ctx = NULL;
    
    if (PyLong_Check(ssl_ctx_ptr_obj)) {
        ssl_ctx = (SSL_CTX *)PyLong_AsVoidPtr(ssl_ctx_ptr_obj);
    } else {
        PyErr_SetString(PyExc_TypeError, "SSL_CTX pointer must be an integer");
        return NULL;
    }
    
    if (!ssl_ctx) {
        PyErr_SetString(PyExc_ValueError, "Invalid SSL_CTX pointer");
        return NULL;
    }
    
    /* Increment reference to OCSP response to keep it alive */
    Py_INCREF(ocsp_response_obj);
    
    /* Set OCSP stapling callback (based on Exim's approach) */
    SSL_CTX_set_tlsext_status_cb(ssl_ctx, ocsp_stapling_callback);
    SSL_CTX_set_tlsext_status_arg(ssl_ctx, ocsp_response_obj);
    
    Py_RETURN_NONE;
}

/* Method definitions */
static PyMethodDef ocsp_stapling_methods[] = {
    {
        "enable_ocsp_stapling",
        py_enable_ocsp_stapling,
        METH_VARARGS,
        "Enable OCSP stapling on SSL context (requires SSL_CTX access)"
    },
    {
        "set_ocsp_response_callback",
        py_set_ocsp_response_callback,
        METH_VARARGS,
        "Set OCSP response callback on SSL_CTX pointer (from ctypes)"
    },
    {
        "get_ssl_ctx_from_context",
        py_get_ssl_ctx_from_context,
        METH_VARARGS,
        "Extract SSL_CTX pointer from Python ssl.SSLContext (implementation-dependent)"
    },
    {NULL, NULL, 0, NULL}  /* Sentinel */
};

/* Module definition */
static struct PyModuleDef ocsp_stapling_module = {
    PyModuleDef_HEAD_INIT,
    "ocsp_stapling_extension",
    "OCSP Stapling C Extension - Based on Exim's implementation",
    sizeof(module_state),
    ocsp_stapling_methods,
    NULL,
    NULL,
    NULL,
    NULL
};

/* Module initialization */
PyMODINIT_FUNC PyInit_ocsp_stapling_extension(void) {
    PyObject *module;
    module_state *state;
    
    module = PyModule_Create(&ocsp_stapling_module);
    if (module == NULL) {
        return NULL;
    }
    
    state = get_module_state(module);
    if (state == NULL) {
        Py_DECREF(module);
        return NULL;
    }
    
    state->ocsp_response_cache = PyDict_New();
    if (state->ocsp_response_cache == NULL) {
        Py_DECREF(module);
        return NULL;
    }
    
    return module;
}

