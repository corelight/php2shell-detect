module PHP2SHELL;

# Prefix classification and bounded body searches share these definitions.

# Field-name case is significant. Quoted and unquoted MIME parameters
# are supported; matching does not depend on a particular boundary.
const upload_progress_name = /(^|;)[ \t]*name=(\"PHP_SESSION_UPLOAD_PROGRESS\"|PHP_SESSION_UPLOAD_PROGRESS)([ \t]*;|[ \t]*$)/;

const serialized_array_start = /^a:[0-9]+:\{/;
const serialized_array_partial = /^(a(:[0-9]*(:)?)?)?$/;

## table[pattern] matches the whole string. Newline-aware wrappers make
## these substring searches over a bounded chunk plus overlap.
## These indicators do not cover every PHP lifecycle failure.
const body_markers = table(
	[/(.|\n)*i:-?[1-9][0-9]{19,};(.|\n)*/] = "serialized-integer-overflow",
	[/(.|\n)*i:0;N;i:4294967296;N;i:8589934592;N;(.|\n)*/] =
		"serialized-integer-collisions",
	[/(.|\n)*(s:34:\"(Aa|B@){17}\";(N;|S:1:\"x\";)){3}(.|\n)*/] =
		"serialized-string-collisions",
	[/(.|\n)*a:600000:\{(i:0;N;){4}(.|\n)*/] = "serialized-duplicate-array",
	[/(.|\n)*(i:[0-9]+;O:1:\"X\":0:\{\}){4}(.|\n)*/] =
		"serialized-object-repetition",
);

const body_notice_types = table(
	["serialized-integer-overflow"] = Serialized_Integer_Overflow,
	["serialized-integer-collisions"] = Serialized_Integer_Collisions,
	["serialized-string-collisions"] = Serialized_String_Collisions,
	["serialized-duplicate-array"] = Serialized_Duplicate_Array,
	["serialized-object-repetition"] = Serialized_Object_Repetition,
);
