#!/usr/bin/env python3
"""Measure X HTTPS URL tests after connection and TLS establishment."""
from pathlib import Path
import argparse


def prepare(source: Path) -> None:
    path = source / 'common/urltest/urltest.go'
    text = path.read_text(encoding='utf-8')
    marker = '// X: measure the request on the established connection.'
    if marker not in text:
        old = '\tresp, err := client.Do(req.WithContext(ctx))'
        if text.count(old) != 1:
            raise ValueError('Upstream URLTest changed; review timing patch')
        text = text.replace('"net/http"', '"net/http"\n\t"net/http/httptrace"', 1)
        text = text.replace(old, '''\t// X: measure the request on the established connection.
\t// GotConn runs after TLS completes. The original context and client
\t// timeout still cover dial/TLS, including failures, for every caller.
\ttrace := &httptrace.ClientTrace{GotConn: func(httptrace.GotConnInfo) {
\t\tstart = time.Now()
\t}}
\tresp, err := client.Do(req.WithContext(httptrace.WithClientTrace(ctx, trace)))''')
        path.write_text(text, encoding='utf-8', newline='\n')
    test = Path(__file__).with_name('latency-tests') / 'urltest_timing_test.go'
    (path.parent / test.name).write_text(test.read_text(encoding='utf-8'), encoding='utf-8', newline='\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path)
    prepare(parser.parse_args().source.resolve())
