from django.core.cache import cache
from django_redis import get_redis_connection


class TestDjangoRedis:
    def test_clear_all_caches(self):
        response = get_redis_connection("default").flushall()
        assert response

    def test_add_data_in_cache(self):
        response = cache.set("foo", "value", timeout=25)
        assert response

    def test_get_data_from_cache(self):
        response = cache.get("foo")
        assert response
        assert response == "value"

    def test_get_ttl_from_cache(self):
        ttl = cache.ttl("foo")
        assert ttl
        assert isinstance(ttl, int)
