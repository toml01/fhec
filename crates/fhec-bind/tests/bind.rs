//! Integration tests: parse inline sources with the solar parser fork inside one
//! session/arena scope, bind, and assert resolutions — the same shape the real
//! pipeline uses.

use fhec_bind::*;
use solar_parse::{
    ast,
    ast::visit::Visit,
    interface::{source_map::FileName, ColorChoice, Ident, Session},
    Parser,
};
use std::ops::ControlFlow;

/// Parses `sources` (name, text) into one arena, binds them, and runs `f` inside the
/// session scope.
fn with_bound<R: Send>(
    sources: &[(&str, &str)],
    f: impl for<'ast> FnOnce(&BoundUnit<'ast>, &[&'ast ast::SourceUnit<'ast>]) -> R + Send,
) -> R {
    let sess = Session::builder()
        .with_buffer_emitter(ColorChoice::Never)
        .build();
    sess.enter(|| {
        let arena = ast::Arena::new();
        let mut files = Vec::new();
        let mut asts: Vec<&ast::SourceUnit<'_>> = Vec::new();
        for (name, src) in sources {
            let mut parser = Parser::from_source_code(
                &sess,
                &arena,
                FileName::Custom((*name).to_string()),
                (*src).to_string(),
            )
            .expect("source registration must succeed");
            let unit = match parser.parse_file() {
                Ok(u) => u,
                Err(e) => {
                    e.emit();
                    panic!("test source {name} must parse");
                }
            };
            let unit: &ast::SourceUnit<'_> = arena.alloc(unit);
            asts.push(unit);
            files.push(SourceFile {
                name: (*name).to_string(),
                ast: unit,
            });
        }
        f(&bind(files), &asts)
    })
}

/// Collects every identifier occurrence in an AST.
struct Idents(Vec<Ident>);

impl<'ast> Visit<'ast> for Idents {
    type BreakValue = ();

    fn visit_ident(&mut self, ident: &'ast Ident) -> ControlFlow<()> {
        self.0.push(*ident);
        ControlFlow::Continue(())
    }
}

fn idents_named<'ast>(unit_ast: &'ast ast::SourceUnit<'ast>, name: &str) -> Vec<Ident> {
    let mut c = Idents(Vec::new());
    let _ = c.visit_source_unit(unit_ast);
    c.0.into_iter().filter(|i| i.as_str() == name).collect()
}

/// The resolutions recorded for identifier *uses* named `name` (declaration
/// occurrences have no recorded resolution and are filtered out).
fn resolutions_of<'ast>(
    bound: &BoundUnit<'ast>,
    unit_ast: &'ast ast::SourceUnit<'ast>,
    name: &str,
) -> Vec<Resolution> {
    idents_named(unit_ast, name)
        .into_iter()
        .filter_map(|i| bound.resolve(i).cloned())
        .collect()
}

#[test]
fn state_vars_params_and_shadowing() {
    let src = r"
        pragma solidity ^0.8.25;
        contract A {
            uint256 total;
            function f(uint256 p) public { total = p; }
        }
        contract B {
            uint256 x;
            function g() public returns (uint256) {
                uint256 x = 1;
                return x;
            }
        }
    ";
    with_bound(&[("t.sol", src)], |bound, asts| {
        assert!(bound.contract_by_name("A").is_some());
        assert!(bound.contract_by_name("B").is_some());

        let total = resolutions_of(bound, asts[0], "total");
        assert!(
            matches!(total.as_slice(), [Resolution::StateVar(_)]),
            "{total:?}"
        );

        let p = resolutions_of(bound, asts[0], "p");
        assert!(matches!(p.as_slice(), [Resolution::Param(_)]), "{p:?}");

        // The use of `x` in `return x` sees the local, not B's state var.
        let x = resolutions_of(bound, asts[0], "x");
        assert!(matches!(x.as_slice(), [Resolution::Local(_)]), "{x:?}");

        assert!(bound.diagnostics().is_empty(), "{:?}", bound.diagnostics());
    });
}

#[test]
fn unnamed_returns_are_collected_and_their_types_are_resolved() {
    let src = r#"
        pragma solidity ^0.8.25;
        import {euint64} from "@fhenixprotocol/cofhe-contracts/FHE.sol";
        contract C {
            function unnamed(euint64 a) internal returns (euint64) { return a; }
            function named(euint64 a) internal returns (euint64 out) { out = a; }
        }
    "#;
    with_bound(&[("t.sol", src)], |bound, _| {
        for name in ["unnamed", "named"] {
            let (_, function) = bound
                .functions()
                .find(|(_, f)| f.name_str.as_deref() == Some(name))
                .expect("function is collected");
            assert_eq!(function.returns.len(), 1, "function: {name}");
            let ret = bound.var(function.returns[0]);
            assert!(matches!(ret.owner, VarOwner::Return(_)));
            assert!(
                matches!(
                    bound.resolve_span(ret.decl.ty.span),
                    Some(Resolution::External { .. })
                ),
                "function: {name}"
            );
        }
    });
}

#[test]
fn imports_aliased_glob_and_namespace() {
    let a = r"
        pragma solidity ^0.8.25;
        contract A { }
        function util() pure { }
    ";
    let b = r#"
        pragma solidity ^0.8.25;
        import {A as AA, util} from "./a.sol";
        import * as NS from "./a.sol";
        contract B {
            function h() public {
                AA a = new AA();
                util();
                NS.util();
                a;
            }
        }
    "#;
    with_bound(&[("a.sol", a), ("b.sol", b)], |bound, asts| {
        let a_id = bound.contract_by_name("A").unwrap();

        let aa = resolutions_of(bound, asts[1], "AA");
        assert!(!aa.is_empty());
        assert!(
            aa.iter().all(|r| *r == Resolution::Contract(a_id)),
            "{aa:?}"
        );

        let util = resolutions_of(bound, asts[1], "util");
        assert!(
            matches!(util.as_slice(), [Resolution::Function(_)]),
            "{util:?}"
        );

        let a_fid = bound.file_id("a.sol").unwrap();
        let ns = resolutions_of(bound, asts[1], "NS");
        assert!(
            ns.iter().all(|r| *r == Resolution::Namespace(a_fid)),
            "{ns:?}"
        );

        // NS.util resolves through the namespace helper.
        let util_sym = idents_named(asts[1], "util")[0].name;
        assert!(matches!(
            bound.namespace_member(a_fid, util_sym),
            Some(Resolution::Function(_))
        ));

        assert!(bound.diagnostics().is_empty(), "{:?}", bound.diagnostics());
    });
}

#[test]
fn inheritance_lookup_and_private_exclusion() {
    let src = r"
        pragma solidity ^0.8.25;
        contract Base {
            uint256 val;
            uint256 private hidden;
            function ping() public { }
        }
        contract Kid is Base {
            function h() public {
                val = 1;
                ping();
                hidden = 2;
            }
        }
    ";
    with_bound(&[("t.sol", src)], |bound, asts| {
        let kid = bound.contract_by_name("Kid").unwrap();
        let base = bound.contract_by_name("Base").unwrap();

        let lin = bound.linearization(kid);
        assert!(lin.complete);
        assert_eq!(lin.order, vec![kid, base]);

        let val = resolutions_of(bound, asts[0], "val");
        assert!(
            matches!(val.as_slice(), [Resolution::StateVar(_)]),
            "{val:?}"
        );

        let ping = resolutions_of(bound, asts[0], "ping");
        assert!(
            matches!(ping.as_slice(), [Resolution::Function(_)]),
            "{ping:?}"
        );

        // `hidden` is private in Base: not visible from Kid, and not silently
        // resolved to anything else.
        let hidden = resolutions_of(bound, asts[0], "hidden");
        assert!(
            matches!(
                hidden.as_slice(),
                [Resolution::Unresolved(UnresolvedReason::NotFound)]
            ),
            "{hidden:?}"
        );
    });
}

#[test]
fn c3_diamond_and_inconsistency() {
    let src = r"
        pragma solidity ^0.8.25;
        contract A { }
        contract B is A { }
        contract C is A { }
        contract D is B, C { }
    ";
    with_bound(&[("t.sol", src)], |bound, _| {
        let (a, b, c, d) = (
            bound.contract_by_name("A").unwrap(),
            bound.contract_by_name("B").unwrap(),
            bound.contract_by_name("C").unwrap(),
            bound.contract_by_name("D").unwrap(),
        );
        let lin = bound.linearization(d);
        assert!(lin.complete);
        assert_eq!(
            lin.order,
            vec![d, c, b, a],
            "Solidity linearizes D, C, B, A"
        );
    });

    let bad = r"
        pragma solidity ^0.8.25;
        contract A { }
        contract B { }
        contract C is A, B { }
        contract D is B, A { }
        contract E is C, D { }
    ";
    with_bound(&[("t.sol", bad)], |bound, _| {
        let e = bound.contract_by_name("E").unwrap();
        let lin = bound.linearization(e);
        assert!(!lin.complete);
        assert_eq!(lin.reason, Some(IncompleteReason::LinearizationFailed));
    });
}

#[test]
fn using_for_method_bindings() {
    let src = r"
        pragma solidity ^0.8.25;
        library Math {
            function add2(uint256 a, uint256 b) internal pure returns (uint256) {
                return a + b;
            }
        }
        using Math for uint256;
        using {Math.add2} for euint32 global;
        contract U { }
    ";
    with_bound(&[("t.sol", src)], |bound, asts| {
        let file = bound.file_id("t.sol").unwrap();
        let add2 = idents_named(asts[0], "add2")[0].name;

        // `using Math for uint256;` (library form)
        let m = bound.method_candidates(None, file, "uint256", add2);
        assert!(
            matches!(m, MethodResolution::Functions(ref f) if f.len() == 1),
            "{m:?}"
        );

        // `using {Math.add2} for euint32 global;` (function-list form, global)
        let m = bound.method_candidates(None, file, "euint32", add2);
        assert!(
            matches!(m, MethodResolution::Functions(ref f) if f.len() == 1),
            "{m:?}"
        );

        // No binding for an unrelated type.
        let m = bound.method_candidates(None, file, "uint8", add2);
        assert_eq!(m, MethodResolution::NoBinding);
    });
}

#[test]
fn external_base_makes_inherited_surface_incomplete() {
    let src = r#"
        pragma solidity ^0.8.25;
        import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
        contract C is Ownable {
            uint256 mine;
            function f() public {
                mine = 1;
                transferOwnership(address(1));
            }
        }
    "#;
    with_bound(&[("t.sol", src)], |bound, asts| {
        let c = bound.contract_by_name("C").unwrap();

        // Own members still resolve.
        let mine = resolutions_of(bound, asts[0], "mine");
        assert!(
            matches!(mine.as_slice(), [Resolution::StateVar(_)]),
            "{mine:?}"
        );

        // Unknown names degrade instead of falling through to file scope.
        let t = resolutions_of(bound, asts[0], "transferOwnership");
        assert!(
            matches!(
                t.as_slice(),
                [Resolution::Unresolved(
                    UnresolvedReason::IncompleteInheritance { .. }
                )]
            ),
            "{t:?}"
        );

        let lin = bound.linearization(c);
        assert!(!lin.complete);
        assert_eq!(lin.reason, Some(IncompleteReason::ExternalBase));
        assert!(matches!(
            bound.contract(c).bases.as_slice(),
            [BaseRef::External { .. }]
        ));
    });
}

#[test]
fn file_scope_names_survive_incomplete_inheritance() {
    let src = r#"
        pragma solidity ^0.8.25;
        import {ExternalBase, importedFn} from "@vendor/External.sol";
        library L { function pub(uint256 value) internal returns (uint256) { return value; } }
        function freeFn(uint256 value) pure returns (uint256) { return value; }
        contract C is ExternalBase {
            function f(uint256 value) public returns (uint256) {
                msg.sender;
                importedFn(value);
                return L.pub(freeFn(value));
            }
        }
    "#;
    with_bound(&[("t.sol", src)], |bound, asts| {
        assert!(matches!(
            resolutions_of(bound, asts[0], "L").as_slice(),
            [Resolution::Contract(_)]
        ));
        assert!(matches!(
            resolutions_of(bound, asts[0], "freeFn").as_slice(),
            [Resolution::Function(_)]
        ));
        assert!(matches!(
            resolutions_of(bound, asts[0], "importedFn").as_slice(),
            [Resolution::External { .. }]
        ));
        assert!(matches!(
            resolutions_of(bound, asts[0], "msg").as_slice(),
            [Resolution::Builtin(_)]
        ));
    });
}

#[test]
fn known_inherited_prefix_survives_an_opaque_ancestor() {
    let src = r#"
        pragma solidity ^0.8.25;
        import {ExternalBase} from "@vendor/External.sol";
        contract Core is ExternalBase {
            function helper(uint256 value) internal returns (uint256) { return value; }
        }
        contract Child is Core {
            function f(uint256 value) public returns (uint256) { return helper(value); }
        }
    "#;
    with_bound(&[("t.sol", src)], |bound, asts| {
        assert!(matches!(
            resolutions_of(bound, asts[0], "helper").as_slice(),
            [Resolution::Function(_)]
        ));
    });
}

#[test]
fn opaque_higher_priority_base_still_blocks_a_known_lower_member() {
    let src = r#"
        pragma solidity ^0.8.25;
        import {ExternalBase} from "@vendor/External.sol";
        contract Known {
            function unsafeHelper(uint256 value) internal returns (uint256) { return value; }
            function safeHelper(uint256 value) internal returns (uint256) { return value; }
        }
        contract Unsafe is Known, ExternalBase {
            function f(uint256 value) public returns (uint256) { return unsafeHelper(value); }
        }
        contract Safe is ExternalBase, Known {
            function f(uint256 value) public returns (uint256) { return safeHelper(value); }
        }
    "#;
    with_bound(&[("t.sol", src)], |bound, asts| {
        assert!(matches!(
            resolutions_of(bound, asts[0], "unsafeHelper").as_slice(),
            [Resolution::Unresolved(
                UnresolvedReason::IncompleteInheritance { .. }
            )]
        ));
        assert!(matches!(
            resolutions_of(bound, asts[0], "safeHelper").as_slice(),
            [Resolution::Function(_)]
        ));
    });
}

#[test]
fn named_external_import_is_precise() {
    let src = r#"
        pragma solidity ^0.8.25;
        import {FHE, euint32} from "@fhenixprotocol/cofhe-contracts/FHE.sol";
        contract K {
            euint32 v;
            function f() public {
                FHE.allowThis(v);
            }
        }
    "#;
    with_bound(&[("t.sol", src)], |bound, asts| {
        let fhe = resolutions_of(bound, asts[0], "FHE");
        assert!(
            matches!(
                fhe.as_slice(),
                [Resolution::External { specifier, member: Some(_) }]
                    if specifier == "@fhenixprotocol/cofhe-contracts/FHE.sol"
            ),
            "{fhe:?}"
        );

        let e32 = resolutions_of(bound, asts[0], "euint32");
        assert!(!e32.is_empty());
        assert!(
            e32.iter().all(|r| matches!(r, Resolution::External { .. })),
            "{e32:?}"
        );

        let v = resolutions_of(bound, asts[0], "v");
        assert!(matches!(v.as_slice(), [Resolution::StateVar(_)]), "{v:?}");
    });
}

#[test]
fn plain_external_import_degrades_unknowns() {
    let src = r#"
        pragma solidity ^0.8.25;
        import "@fhenixprotocol/cofhe-contracts/FHE.sol";
        contract P {
            function f() public {
                FHE.asEuint32(1);
            }
        }
    "#;
    with_bound(&[("t.sol", src)], |bound, asts| {
        let fhe = resolutions_of(bound, asts[0], "FHE");
        assert!(
            matches!(
                fhe.as_slice(),
                [Resolution::Unresolved(UnresolvedReason::MaybeExternal { specifiers })]
                    if specifiers == &["@fhenixprotocol/cofhe-contracts/FHE.sol".to_string()]
            ),
            "{fhe:?}"
        );
        assert!(bound.diagnostics().is_empty(), "{:?}", bound.diagnostics());
    });
}

#[test]
fn unresolvable_relative_import_is_fhe1003() {
    let src = r#"
        pragma solidity ^0.8.25;
        import "./missing.sol";
        contract M {
            function f() public {
                Foo x = Foo(address(0));
                x;
            }
        }
    "#;
    with_bound(&[("t.sol", src)], |bound, asts| {
        assert!(
            bound
                .diagnostics()
                .iter()
                .any(|d| d.code == CODE_UNRESOLVED_IMPORT),
            "{:?}",
            bound.diagnostics()
        );
        // The failed import still degrades unknown names conservatively.
        let foo = resolutions_of(bound, asts[0], "Foo");
        assert!(
            foo.iter().all(|r| matches!(
                r,
                Resolution::Unresolved(UnresolvedReason::MaybeExternal { .. })
            )),
            "{foo:?}"
        );
    });
}

#[test]
fn duplicate_definitions_are_fhe1020() {
    let src = r"
        pragma solidity ^0.8.25;
        contract D2 {
            uint256 a;
            uint256 a;
            function f() public {
                uint256 b;
                uint256 b;
                b;
            }
        }
    ";
    with_bound(&[("t.sol", src)], |bound, _| {
        let dups: Vec<_> = bound
            .diagnostics()
            .iter()
            .filter(|d| d.code == CODE_DUPLICATE_DEFINITION)
            .collect();
        assert_eq!(dups.len(), 2, "{dups:?}");
    });
}

#[test]
fn builtins_resolve() {
    let src = r"
        pragma solidity ^0.8.25;
        contract Bn {
            address owner;
            function f() public {
                owner = msg.sender;
                require(true);
            }
        }
    ";
    with_bound(&[("t.sol", src)], |bound, asts| {
        let msg = resolutions_of(bound, asts[0], "msg");
        assert!(
            matches!(msg.as_slice(), [Resolution::Builtin(_)]),
            "{msg:?}"
        );
        let req = resolutions_of(bound, asts[0], "require");
        assert!(
            matches!(req.as_slice(), [Resolution::Builtin(_)]),
            "{req:?}"
        );
    });
}
