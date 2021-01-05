#  BSD 3-Clause License
#
#  Copyright (c) 2012, the Sentry Team, see AUTHORS for more details
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


from __future__ import absolute_import

import starlette
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response
from starlette.types import ASGIApp

import zuqa
import zuqa.instrumentation.control
from zuqa.base import Client
from zuqa.conf import constants
from zuqa.contrib.asyncio.traces import set_context
from zuqa.contrib.starlette.utils import get_data_from_request, get_data_from_response
from zuqa.utils.disttracing import TraceParent
from zuqa.utils.logging import get_logger

logger = get_logger("zuqa.errors.client")


def make_apm_client(config: dict, client_cls=Client, **defaults) -> Client:
    """Builds ZUQA client.

    Args:
        config (dict): Dictionary of Client configuration. All keys must be uppercase. See `zuqa.conf.Config`.
        client_cls (Client): Must be Client or its child.
        **defaults: Additional parameters for Client. See `zuqa.base.Client`

    Returns:
        Client
    """
    if "framework_name" not in defaults:
        defaults["framework_name"] = "starlette"
        defaults["framework_version"] = starlette.__version__

    return client_cls(config, **defaults)


class ZUQA(BaseHTTPMiddleware):
    """
    Starlette / FastAPI middleware for ZUQA capturing.

    >>> zuqa = make_apm_client({
        >>> 'SERVICE_NAME': 'myapp',
        >>> 'DEBUG': True,
        >>> 'SERVER_URL': 'http://localhost:32140',
        >>> 'CAPTURE_HEADERS': True,
        >>> 'CAPTURE_BODY': 'all'
    >>> })

    >>> app.add_middleware(ZUQA, client=zuqa)

    Pass an arbitrary APP_NAME and SECRET_TOKEN::

    >>> zuqa = ZUQA(app, service_name='myapp', secret_token='asdasdasd')

    Pass an explicit client::

    >>> zuqa = ZUQA(app, client=client)

    Automatically configure logging::

    >>> zuqa = ZUQA(app, logging=True)

    Capture an exception::

    >>> try:
    >>>     1 / 0
    >>> except ZeroDivisionError:
    >>>     zuqa.capture_exception()

    Capture a message::

    >>> zuqa.capture_message('hello, world!')
    """

    def __init__(self, app: ASGIApp, client: Client):
        """

        Args:
            app (ASGIApp): Starlette app
            client (Client): ZUQA Client
        """
        self.client = client

        if self.client.config.instrument:
            zuqa.instrumentation.control.instrument()

        super().__init__(app)

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        """Processes the whole request APM capturing.

        Args:
            request (Request)
            call_next (RequestResponseEndpoint): Next request process in Starlette.

        Returns:
            Response
        """
        await self._request_started(request)

        try:
            response = await call_next(request)
        except Exception:
            await self.capture_exception(
                context={"request": await get_data_from_request(request, self.client.config, constants.ERROR)}
            )
            zuqa.set_transaction_result("HTTP 5xx", override=False)
            zuqa.set_context({"status_code": 500}, "response")

            raise
        else:
            await self._request_finished(response)
        finally:
            self.client.end_transaction()

        return response

    async def capture_exception(self, *args, **kwargs):
        """Captures your exception.

        Args:
            *args:
            **kwargs:
        """
        self.client.capture_exception(*args, **kwargs)

    async def capture_message(self, *args, **kwargs):
        """Captures your message.

        Args:
            *args: Whatever
            **kwargs: Whatever
        """
        self.client.capture_message(*args, **kwargs)

    async def _request_started(self, request: Request):
        """Captures the begin of the request processing to APM.

        Args:
            request (Request)
        """
        trace_parent = TraceParent.from_headers(dict(request.headers))
        self.client.begin_transaction("request", trace_parent=trace_parent)

        await set_context(lambda: get_data_from_request(request, self.client.config, constants.TRANSACTION), "request")
        zuqa.set_transaction_name("{} {}".format(request.method, request.url.path), override=False)

    async def _request_finished(self, response: Response):
        """Captures the end of the request processing to APM.

        Args:
            response (Response)
        """
        await set_context(
            lambda: get_data_from_response(response, self.client.config, constants.TRANSACTION), "response"
        )

        result = "HTTP {}xx".format(response.status_code // 100)
        zuqa.set_transaction_result(result, override=False)
