// ole32: the COM run-time library.
//
// The types they name are in libc and in the platform's windows.h —
// GUID, REFIID, CLSCTX, HRESULT and the interface pointer types.

typedef void *IUnknown;
typedef void *IDispatch;
typedef void *CLSID;
typedef void *REFIID;
typedef void *LPCOLESTR;
typedef void **PPVOID;
typedef void *LPCVOID;
typedef long HRESULT;

HRESULT CoInitialize(LPVOID reserved);
HRESULT CoInitializeEx(LPVOID reserved, DWORD dwCoInit);
HRESULT CoInitializeSecurity(LPVOID pSecDesc, long cAuthSvc, LPVOID asAuthSvc, LPVOID pReserved1, DWORD dwAuthnLevel, DWORD dwImpLevel, LPVOID pAuthList, DWORD dwAuthnCapabilities, LPVOID pReserved3);
HRESULT CoUninitialize(void);
HRESULT CoCreateInstance(const void *rclsid, void *pUnkOuter, DWORD dwClsContext, const void *pvReserved, void **ppv);
DWORD CoRegisterClassObject(const void *clsid, void *pUnk, DWORD dwClsContext, DWORD dwRegister, DWORD *pdwRegister);
HRESULT CoRevokeClassObject(DWORD dwRegister);
HRESULT CoGetClassObject(const void *refclsid, DWORD dwClsContext, LPVOID pvReserved, const void *riid, void **ppv);
HRESULT CoCreateGuid(GUID *pguid);
HRESULT CoTaskMemFree(void *pv);
