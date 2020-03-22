;;; the smallest possible slicism program
;;;
;;; returns a 204 response
;;;
(module
  (import "env" "write_meta" (func $writeMeta (param i32 i32) (result i32)))
  (memory 1)

  (func (export "slice_start")
    ;; store the following CBOR ({"status":204})
    ;;
    ;; A1                 # map(1)
    ;;    66              # text(6)
    ;;       737461747573 # "status"
    ;;    18 CC           # unsigned(204)
    ;;
    ;; ...via little-endian order i64 and i32

    (i64.store
      (i32.const 0) ;; offset=0
      (i64.const 0x73757461747366a1))

    (i32.store
      (i32.const 8) ;; offset=8
      (i32.const 0x0000CC18))
    
    ;; write it to the response meta
    (call $writeMeta
      (i32.const 0) ;; offset=0
      (i32.const 10)) ;; length = 10

    ;; ignore return value
    drop
  )
)
