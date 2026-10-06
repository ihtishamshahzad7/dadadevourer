import unittest

from scanner.xss import (
    _reflection_context,
    _replace_query_parameter,
    _parameter_names,
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

    def test_reflection_contexts_are_conservative(self):
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
        self.assertEqual(_reflection_context(f"<p>{marker}</p>", marker), "html")
        self.assertEqual(_reflection_context(marker, marker), "text")


if __name__ == "__main__":
    unittest.main()
