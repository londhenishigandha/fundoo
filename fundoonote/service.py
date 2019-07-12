import redis

r = redis.StrictRedis(host='localhost', port=6379, db=0)


class redis_methods:

    def set_token(self, key, value):
        # this method is used to add the data to redis
        r.set(key, value)
        print('token set')

    def get_token(self, key):
        # this method is used to get the data out of redis
        token = r.get(key)
        return token


    def flush(self):
        # this method is used to delete data from redis
        r.flushall()