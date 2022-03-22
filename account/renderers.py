import json
from rest_framework import renderers


class UserRendere(renderers.JSONRenderer):
    charset = 'utf-8'

    def render(self, data, accepted_media_type=None, render_content=None):
        response = ''
        if 'ErroDetais' in str(data):
            response = json.dumps({'errors': data})
        else:
            response = json.dumps(data)
        return response
