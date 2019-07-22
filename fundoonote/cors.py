class CorsMiddleware(object):
    def process_response(self, req, resp):
        response={}
        response["Access-Control-Allow-Origin"] = "*"
        return response
