--TEST--
quic: extension loads and registers the Quic\* classes
--EXTENSIONS--
quic
--FILE--
<?php declare(strict_types=1);

//
// Copyright (c) 2026, Mike Pultz All rights reserved.
//
// Extension loads and registers the Quic\* classes.
//

var_dump(extension_loaded('quic'));
var_dump(class_exists('Quic\\Connection'));
var_dump(class_exists('Quic\\Listener'));
var_dump(class_exists('Quic\\Stream'));
var_dump(class_exists('Quic\\Exception'));
var_dump(is_subclass_of('Quic\\Exception', 'Exception'));
?>
--EXPECT--
bool(true)
bool(true)
bool(true)
bool(true)
bool(true)
bool(true)
