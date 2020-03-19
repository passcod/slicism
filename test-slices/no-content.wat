(module
  (import "env" "exit_set" (func $setExit (param i32)))
  (import "env" "response_status" (func $responseStatus (param i32) (result i32)))

  (func $alloc (export "alloc")
    (param $size i32)
    (param $align i32)
    (result i32) ;; memory
    (result i32) ;; offset
    (result i32) ;; length
    i32.const 0
    i32.const 0
    i32.const 0
  )

  (func $dealloc (export "dealloc")
    (param $mem i32)
    (param $size i32)
    (param $align i32)
  )

  (start $main)
  (func $main
      i32.const 204
      call $responseStatus
      call $setExit
  )
)
