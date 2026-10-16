"""Read capability metadata and open a confirmation window; no install/file API."""
class ClientBridge:
    def __init__(self,app,version):self._app=app;self._version=version
    def get_client_capabilities(self):return {'desktop_updates':True,'desktop_version':self._version}
    def show_program_update(self):
        self._app.check_online_update();return {'opened':True}
