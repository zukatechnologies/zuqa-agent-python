#  BSD 3-Clause License
#
#  Copyright (c) 2019, Elasticsearch BV
#  All rights reserved.
#
#  Redistribution and use in source and binary forms, with or without
#  modification, are permitted provided that the following conditions are met:
#
#  * Redistributions of source code must retain the above copyright notice, this
#    list of conditions and the following disclaimer.
#
#  * Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
#
#  * Neither the name of the copyright holder nor the names of its
#    contributors may be used to endorse or promote products derived from
#    this software without specific prior written permission.
#
#  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
#  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
#  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
#  DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
#  FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
#  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
#  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
#  CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
#  OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
#  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

import sys

from zuqa.utils.module_import import import_string

_cls_register = {
    "zuqa.instrumentation.packages.botocore.BotocoreInstrumentation",
    "zuqa.instrumentation.packages.jinja2.Jinja2Instrumentation",
    "zuqa.instrumentation.packages.psycopg2.Psycopg2Instrumentation",
    "zuqa.instrumentation.packages.psycopg2.Psycopg2ExtensionsInstrumentation",
    "zuqa.instrumentation.packages.mysql.MySQLInstrumentation",
    "zuqa.instrumentation.packages.mysql_connector.MySQLConnectorInstrumentation",
    "zuqa.instrumentation.packages.pymysql.PyMySQLConnectorInstrumentation",
    "zuqa.instrumentation.packages.pylibmc.PyLibMcInstrumentation",
    "zuqa.instrumentation.packages.pymongo.PyMongoInstrumentation",
    "zuqa.instrumentation.packages.pymongo.PyMongoBulkInstrumentation",
    "zuqa.instrumentation.packages.pymongo.PyMongoCursorInstrumentation",
    "zuqa.instrumentation.packages.python_memcached.PythonMemcachedInstrumentation",
    "zuqa.instrumentation.packages.pymemcache.PyMemcacheInstrumentation",
    "zuqa.instrumentation.packages.redis.RedisInstrumentation",
    "zuqa.instrumentation.packages.redis.RedisPipelineInstrumentation",
    "zuqa.instrumentation.packages.redis.RedisConnectionInstrumentation",
    "zuqa.instrumentation.packages.requests.RequestsInstrumentation",
    "zuqa.instrumentation.packages.sqlite.SQLiteInstrumentation",
    "zuqa.instrumentation.packages.urllib3.Urllib3Instrumentation",
    "zuqa.instrumentation.packages.elasticsearch.ElasticsearchConnectionInstrumentation",
    "zuqa.instrumentation.packages.elasticsearch.ElasticsearchInstrumentation",
    "zuqa.instrumentation.packages.cassandra.CassandraInstrumentation",
    "zuqa.instrumentation.packages.pymssql.PyMSSQLInstrumentation",
    "zuqa.instrumentation.packages.pyodbc.PyODBCInstrumentation",
    "zuqa.instrumentation.packages.django.template.DjangoTemplateInstrumentation",
    "zuqa.instrumentation.packages.django.template.DjangoTemplateSourceInstrumentation",
    "zuqa.instrumentation.packages.urllib.UrllibInstrumentation",
}

if sys.version_info >= (3, 5):
    _cls_register.update(
        [
            "zuqa.instrumentation.packages.asyncio.sleep.AsyncIOSleepInstrumentation",
            "zuqa.instrumentation.packages.asyncio.aiohttp_client.AioHttpClientInstrumentation",
            "zuqa.instrumentation.packages.asyncio.elasticsearch.ElasticSearchAsyncConnection",
            "zuqa.instrumentation.packages.asyncio.aiopg.AioPGInstrumentation",
            "zuqa.instrumentation.packages.tornado.TornadoRequestExecuteInstrumentation",
            "zuqa.instrumentation.packages.tornado.TornadoHandleRequestExceptionInstrumentation",
            "zuqa.instrumentation.packages.tornado.TornadoRenderInstrumentation",
        ]
    )


def register(cls):
    _cls_register.add(cls)


_instrumentation_singletons = {}


def get_instrumentation_objects():
    for cls_str in _cls_register:
        if cls_str not in _instrumentation_singletons:
            cls = import_string(cls_str)
            _instrumentation_singletons[cls_str] = cls()

        obj = _instrumentation_singletons[cls_str]
        yield obj
