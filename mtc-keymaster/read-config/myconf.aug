module Myconf =
  autoload xfm

  let comment = IniFile.comment "#" "#"
  let sep     = Sep.space

  (* Value body: 1+ chars, no embedded '#' / quotes / newline,
     and no leading or trailing whitespace.                    *)
  let value_re = /[^ \t\r\n#"']|[^ \t\r\n#"'][^\r\n#"']*[^ \t\r\n#"']/
  let value    = Quote.do_quote_opt (store value_re)

  let entry  = [ Util.indent . key IniFile.entry_re . sep . value
                 . (comment | IniFile.eol) ]

  (* Allow standalone comment lines inside a [section] record so
     operators can document tunables alongside the section they
     belong to (issue 6a).  Without this, the lens rejects any
     comment that appears between the [global] header and the next
     section. *)
  let entry_or_comment = entry | comment

  let title  = IniFile.title IniFile.record_re
  let record = IniFile.record title entry_or_comment

  let lns    = IniFile.lns record comment
  let xfm    = transform lns (incl "/etc/postWolf/config")
