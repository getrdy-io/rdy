//! The macro behind every open string enum of the result format.

/// Defines an enum for a snake_case code that newer producers may extend.
///
/// The enum has one variant per known text and an `Unknown(String)` variant that keeps any other text
/// exactly as read, so a value this version does not know survives a read and a write (01 section 3.2,
/// "Open"). Reading never fails on the text. The `Unknown` variant is where a consumer applies its rule
/// for values it cannot read.
///
/// The doc comment of the enum is the description in the JSON schema, which lists the known values and
/// also accepts any snake_case code (the `OpenCode` definition).
macro_rules! open_enum {
    (
        $(#[doc = $doc:literal])*
        $name:ident {
            $( $(#[$vmeta:meta])* $variant:ident => $text:literal ),+ $(,)?
        }
    ) => {
        $(#[doc = $doc])*
        #[derive(Debug, Clone, PartialEq, Eq, Hash)]
        #[non_exhaustive]
        pub enum $name {
            $( $(#[$vmeta])* $variant, )+
            /// A value this version of rdy-spec does not know, kept as written.
            Unknown(String),
        }

        impl $name {
            /// The wire text of this value.
            #[must_use]
            pub fn as_str(&self) -> &str {
                match self {
                    $( Self::$variant => $text, )+
                    Self::Unknown(other) => other,
                }
            }

            /// `true` when this is [`Self::Unknown`].
            #[must_use]
            pub fn is_unknown(&self) -> bool {
                matches!(self, Self::Unknown(_))
            }
        }

        impl From<&str> for $name {
            fn from(text: &str) -> Self {
                match text {
                    $( $text => Self::$variant, )+
                    other => Self::Unknown(other.to_owned()),
                }
            }
        }

        impl From<String> for $name {
            fn from(text: String) -> Self {
                match text.as_str() {
                    $( $text => Self::$variant, )+
                    _ => Self::Unknown(text),
                }
            }
        }

        impl ::schemars::JsonSchema for $name {
            fn schema_name() -> ::std::borrow::Cow<'static, str> {
                stringify!($name).into()
            }

            fn json_schema(generator: &mut ::schemars::SchemaGenerator) -> ::schemars::Schema {
                let open = generator.subschema_for::<$crate::result::open::OpenCode>();
                ::schemars::json_schema!({
                    "description": concat!($($doc, "\n",)* "Open: a newer producer may send other snake_case values."),
                    "anyOf": [
                        { "enum": [ $($text),+ ] },
                        open
                    ]
                })
            }
        }

        impl ::std::fmt::Display for $name {
            fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
                f.write_str(self.as_str())
            }
        }

        impl ::serde::Serialize for $name {
            fn serialize<S: ::serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.serialize_str(self.as_str())
            }
        }

        impl<'de> ::serde::Deserialize<'de> for $name {
            fn deserialize<D: ::serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                <String as ::serde::Deserialize>::deserialize(deserializer).map(Self::from)
            }
        }
    };
}

pub(crate) use open_enum;

/// Any snake_case code: the second alternative of every open enum in the schema.
///
/// It exists only to give the schema one shared definition. No value of this type is ever built.
pub(crate) struct OpenCode;

impl ::schemars::JsonSchema for OpenCode {
    fn schema_name() -> ::std::borrow::Cow<'static, str> {
        "OpenCode".into()
    }

    fn json_schema(_: &mut ::schemars::SchemaGenerator) -> ::schemars::Schema {
        ::schemars::json_schema!({
            "description": "A snake_case code. Newer producers may send values not listed.",
            "type": "string",
            "pattern": "^[a-z][a-z0-9_]{0,63}$"
        })
    }
}
