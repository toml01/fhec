//! Index newtypes for the flat side tables of a [`BoundUnit`](crate::BoundUnit).

macro_rules! id_type {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name(u32);

        impl $name {
            pub(crate) fn new(index: usize) -> Self {
                Self(u32::try_from(index).expect("id overflow"))
            }

            /// The index into the corresponding side table.
            pub fn index(self) -> usize {
                self.0 as usize
            }
        }
    };
}

id_type!(
    /// Identifies a source file in the compilation unit.
    FileId
);
id_type!(
    /// Identifies a contract, interface, library, or abstract contract.
    ContractId
);
id_type!(
    /// Identifies a function, constructor, modifier, fallback, or receive definition.
    FunctionId
);
id_type!(
    /// Identifies a variable declaration (state var, param, return var, local, file const,
    /// struct field).
    VarId
);
id_type!(
    /// Identifies a struct, enum, or user-defined value type declaration.
    TypeDeclId
);
id_type!(
    /// Identifies an event declaration.
    EventId
);
id_type!(
    /// Identifies an error declaration.
    ErrorId
);
