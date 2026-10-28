//! The macro behind every open string enum of the result format.

/// Defines an enum for a snake_case code that newer producers may extend.
///
/// The enum has one variant per known text and an `Unknown(String)` variant that keeps any other text
/// exactly as read, so a value this version does not know survives a read and a write (01 section 3.2,
/// "Open"). Reading never fails on the text. The `Unknown` variant is where a consumer applies its rule
/// for values it cannot read.
macro_rules! open_enum {
    (
        $(#[$meta:meta])*
        $name:ident {
            $( $(#[$vmeta:meta])* $variant:ident => $text:literal ),+ $(,)?
        }
    ) => {
        $(#[$meta])*
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
