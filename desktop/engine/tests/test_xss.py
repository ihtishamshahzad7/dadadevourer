import unittest

from scanner.xss import (
    _reflection_context,
    _replace_query_parameter,
    _parameter_names,
    _safe_form,
    _forms,
)


class ReflectedXssTests(unittest.TestCase):
    def test_parameter_names_are_unique_and_bounded(self):
        target = "https://example.test/search?a=1&a=2&b=3"
        self.assertEqual(_parameter_names(target), ["a", "b"])

    def test_replace_query_parameter_preserves_other_parameters(self):
        target = "https://example.test/search?a=1&b=2"
        updated = _replace_query_parameter(target, "a", "<probe>")
        self.assertIn("a=%3Cprobe%3E", updated)
        self.assertIn("b=2", updated)

    def test_reflection_contexts_cover_modern_html_contexts(self):
        marker = "DADA_XSS_PROBE_abc123"
        self.assertEqual(_reflection_context(f"<div>{marker}</div>", marker), "html")
        self.assertEqual(
            _reflection_context(f'<script>const value="{marker}"</script>', marker),
            "javascript",
        )
        self.assertEqual(
            _reflection_context(f'<input value="{marker}">', marker),
            "attribute",
        )
        self.assertEqual(
            _reflection_context(f'<a href="/search?q={marker}">link</a>', marker),
            "attribute",
        )
        self.assertEqual(
            _reflection_context(f"<style>.x{{background:url({marker})}}</style>", marker),
            "css",
        )
        self.assertEqual(
            _reflection_context(f"<!-- {marker} -->", marker),
            "comment",
        )
        self.assertEqual(_reflection_context(marker, marker), "text")

    def test_form_parser_discovers_get_and_post_inputs(self):
        html = '''
        <form action="/search" method="get">
          <input name="q" value="hello">
        </form>
        <form action="/comment" method="post">
          <textarea name="body"></textarea>
          <input type="submit" value="Save">
        </form>
        '''
        forms = _forms(html)
        self.assertEqual(len(forms), 2)
        self.assertEqual(forms[0]["method"], "get")
        self.assertEqual(forms[1]["method"], "post")
        self.assertEqual(forms[1]["inputs"][0]["name"], "body")

    def test_destructive_forms_are_not_auto_submitted(self):
        self.assertFalse(_safe_form({"action": "/account/delete", "method": "post", "inputs": [{"name": "id"}]}))
        self.assertTrue(_safe_form({"action": "/profile/update", "method": "post", "inputs": [{"name": "bio"}]}))


if __name__ == "__main__":
    unittest.main()
