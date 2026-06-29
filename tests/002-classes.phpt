--TEST--
quic: classes are final with public constructors; static factories removed
--EXTENSIONS--
quic
--FILE--
<?php declare(strict_types=1);

//
// Copyright (c) 2026, Mike Pultz All rights reserved.
//
// Classes are final with public constructors; static factories removed.
//

foreach (['Quic\\Connection', 'Quic\\Listener', 'Quic\\Stream'] as $class)
{
    $rc = new ReflectionClass($class);

    printf("%s: final=%s ctor=%s\n",
        $class,
        $rc->isFinal() == true ? 'yes' : 'no',
        $rc->getConstructor()->isPublic() == true ? 'public' : 'nonpublic');
}

//
// the old static factory methods are gone
//
var_dump(method_exists('Quic\\Connection', 'connect'));
var_dump(method_exists('Quic\\Listener', 'listen'));

//
// openStream() is retained as a convenience alongside new Quic\Stream()
//
var_dump(method_exists('Quic\\Connection', 'openStream'));

//
// the Stream constructor takes a Connection
//
$p = (new ReflectionMethod('Quic\\Stream', '__construct'))->getParameters();
echo "Stream ctor arg0: ", (string)$p[0]->getType(), "\n";
?>
--EXPECT--
Quic\Connection: final=yes ctor=public
Quic\Listener: final=yes ctor=public
Quic\Stream: final=yes ctor=public
bool(false)
bool(false)
bool(true)
Stream ctor arg0: Quic\Connection
