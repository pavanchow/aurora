//! Correctness gate for the embedded Kindling VM: differential testing.
//!
//! For many randomly generated programs, and for a curated set including the
//! math the OS is meant to do (sum of primes below 1000, Carmichael check of
//! 561), the bytecode VM's result must equal the independent tree-walking
//! reference interpreter's result. Two independent evaluators agreeing is the
//! machine-checkable oracle. Program count is controlled by `KINDLING_FUZZ_OPS`
//! (default 500).

use aurora_logic::kref::gen::random_program;
use aurora_logic::{eval_reference, run_kindling};

fn program_count() -> u64 {
    std::env::var("KINDLING_FUZZ_OPS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(500)
}

#[test]
fn vm_matches_reference_interpreter() {
    let count = program_count();
    let mut checked = 0u64;
    for seed in 0..count {
        let ops = (seed as usize % 9) + 3;
        let src = random_program(seed, ops);

        let vm = run_kindling(&src);
        let reference = eval_reference(&src);

        match (vm, reference) {
            (Ok(v), Ok(r)) => {
                assert_eq!(
                    v.0, r.0,
                    "seed {seed}: value mismatch\nVM={:?} REF={:?}\n--- program ---\n{src}",
                    v.0, r.0
                );
                assert_eq!(v.1, r.1, "seed {seed}: output mismatch\n--- program ---\n{src}");
            }
            (Err(ve), Err(re)) => {
                assert_eq!(
                    ve, re,
                    "seed {seed}: error mismatch\nVM={ve:?} REF={re:?}\n--- program ---\n{src}"
                );
            }
            (Ok(v), Err(re)) => panic!(
                "seed {seed}: VM produced {:?} but reference trapped with {re:?}\n--- program ---\n{src}",
                v.0
            ),
            (Err(ve), Ok(r)) => panic!(
                "seed {seed}: VM trapped with {ve:?} but reference produced {:?}\n--- program ---\n{src}",
                r.0
            ),
        }
        checked += 1;
    }
    assert_eq!(checked, count);
    eprintln!("differential: {checked} programs, VM == reference on all");
}

#[test]
fn hand_written_programs_agree() {
    let cases = [
        "return 2 + 3 * 4;",
        "let x = 10; let y = 20; return x * y - 5;",
        "let s = 0; let i = 1; while (i <= 100) { s = s + i; i = i + 1; } return s;",
        "fn fib(n) { if (n < 2) { return n; } return fib(n-1) + fib(n-2); } return fib(15);",
        "fn fact(n) { if (n <= 1) { return 1; } return n * fact(n-1); } return fact(10);",
        "let a = 7; if (a % 2 == 0) { a = a * 2; } else { a = a * 3; } return a;",
        "fn add(a, b) { return a + b; } fn mul(a, b) { return a * b; } return add(mul(2,3), 4);",
        "let x = -5; return -x + 10;",
        "return (1 < 2) == (3 > 2);",
        "let acc = 0; let i = 0; while (i < 10) { if (i % 3 == 0) { acc = acc + i; } i = i + 1; } return acc;",
        "return 7.0 % 3.0;",
        "return 10.5 / 2.0;",
    ];
    for (n, src) in cases.iter().enumerate() {
        let vm = run_kindling(src).unwrap_or_else(|e| panic!("case {n}: VM error {e}"));
        let reference = eval_reference(src).unwrap_or_else(|e| panic!("case {n}: ref error {e}"));
        assert_eq!(vm.0, reference.0, "case {n}: {src}");
        assert_eq!(vm.1, reference.1, "case {n}: {src}");
    }
}

const PRIMES: &str = "\
fn isprime(n){ if(n<2){return false;} let i=2; while(i*i<=n){ if(n%i==0){return false;} i=i+1; } return true; }\
let s=0; let k=2; while(k<1000){ if(isprime(k)){ s=s+k; } k=k+1; } print s; return s;";

const CARMICHAEL: &str = "\
fn isprime(n){ if(n<2){return false;} let i=2; while(i*i<=n){ if(n%i==0){return false;} i=i+1; } return true; }\
let n=561; let carm=1; if(isprime(n)){carm=0;}\
let m=n; let p=2; while(p<=m){ if(m%p==0){ let e=0; while(m%p==0){m=m/p; e=e+1;} if(e>1){carm=0;} if((n-1)%(p-1)!=0){carm=0;} } p=p+1; }\
return carm;";

#[test]
fn sum_of_primes_below_1000_is_76127() {
    use aurora_logic::kindling::Outcome;
    let (v, out) = run_kindling(PRIMES).unwrap();
    assert_eq!(v, Outcome::Int(76127));
    assert_eq!(out.trim(), "76127");
    // The reference interpreter agrees.
    let (rv, _) = eval_reference(PRIMES).unwrap();
    assert_eq!(rv, Outcome::Int(76127));
}

#[test]
fn number_561_is_a_carmichael_number() {
    use aurora_logic::kindling::Outcome;
    let (v, _) = run_kindling(CARMICHAEL).unwrap();
    assert_eq!(v, Outcome::Int(1), "561 = 3*11*17, squarefree, (p-1)|560");
    let (rv, _) = eval_reference(CARMICHAEL).unwrap();
    assert_eq!(rv, Outcome::Int(1));
}
