### Query Structure

The query structure resembles the following:

```
(field_name1:required_value AND field_name2:>50) OR field_name3:"some string value" | groupby field_name1 field_name2 | sortby field_name1 field_name3 | ...
```

Everything the left of the | "pipe" character must be in Lucene syntax.

The operation keywords, such as AND, OR, NOT must always be capitalized.

For more information on the query syntax, refer to the Security Onion documentation and search for `OQL`.