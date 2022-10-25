<?php
namespace MySNMPv2;
require __DIR__ . "/snmp.php";
require __DIR__ . "/mib_compiler.php";
define("SNMP_GET_OUTPUT_PLAIN", 0);
define("SNMP_GET_OUTPUT_OID", 1);
define("SNMP_GET_OUTPUT_TEXT", 2);

define("SNMP_TABLE_OUTPUT_NATIVE", 0);
define("SNMP_TABLE_OUTPUT_ARRAY", 1);
define("SNMP_TABLE_OUTPUT_ASSOC", 2);
define("SNMP_TABLE_OUTPUT_OBJECT_ASSOC", 3);
use snmp;
use mib_compiler;
class MySNMPv2Table
{

}
class MySNMPv2Item
{

}
class MySNMPv2OID
{

}
class MySNMPv2Conn
{

}
class MySNMPv2
{
    private $nodes = array();
    private $mib = NULL;
    protected $host = NULL;
    protected $security = array();
    protected $version = 1;
    protected $timeout = 1;
    private $MIBS = null;
    private $CallString = null;
    protected static $conn = null;
    function __construct($root = 'iso', $loadAll = false)
    {
        $this->nodes = array();
        $this->mib = new MySNMPv2Object();
        $this->MIBS = new MySNMPv2Object();
        if ($loadAll)
        {
            $this->loadAllMibs($root);
        }
    }
    private function loadAllMibs($root = 'iso', $nodes = NULL)
    {
        $this->nodes = $nodes === NULL ? unserialize(file_get_contents(dirname(__FILE__) . DIRECTORY_SEPARATOR . 'oid_format.data')) : $nodes;
        $this->mib = new MySNMPv2Object();
        $this->MIBS = new MySNMPv2Object();
        $this->mib->iso = $this->buildMIB(self::$nodes);
        $this->select($root);
    }
    
    private function mibFileSearch($directory = "/", $mib = null)
      {
        foreach(glob("$directory/*") as $mibfile)
        {
          if(!is_dir($mibfile))
            {
              $x = explode(' DEFINITIONS ::= BEGIN', file_get_contents($mibfile))[0];
              $s = explode("\n", $x);
              $n = str_replace(" ", "", $s[count($s) - 1]);
              
              if($mib === $n)
                {
                  return $mibfile;
                }
            }
        }
        return null;
      }
    private function searchNode(MySNMPv2Object $node, $key = NULL)
    {
        $found = false;
        foreach ($node as $k => $d)
        {
            if ($k === $key)
            {
                $found = true;
                $node = $d;
            }
            else if ($d instanceof MySNMPv2Object)
            {
                $n = $this->searchNode($d, $key);
                if ($n !== false)
                {
                    $found = true;
                    $node = $n;
                }
            }
        }
        if($found)
          {
            return $node;
          }
        return false;
    }
    public function buildMIB($nodes = array() , $name = "iso", $OID = '.1', $MIB = null)
    {
        $mib = new MySNMPv2Object($OID, $name, @$nodes[$name], $MIB);
        foreach (@$nodes[$name] ? : array() as $_OID => $_name)
        {
            $mib->{$_name} = $this->buildMIB($nodes, $_name, $OID . '.' . $_OID, $MIB);
        }
        return $mib;
    }
    
    public function mapMIB($nodes = array() , $name = "iso", $OID = '.1', $MIB = null)
    {
        $mib = new MySNMPv2MapObject($OID, $MIB);
        foreach (@$nodes[$name] ? : array() as $_OID => $_name)
        {
            $mib->{$_name} = $this->mapMIB($nodes, $_name, $OID . '.' . $_OID, $MIB);
        }
        return $mib;
    }
    
    private function select($mib = NULL)
    {
        $selected = self::searchNode(self::$mib, $mib);
        foreach ($selected as $key => $data)
        {
            $this->{$key} = $data;
        }
    }
    public function snmp_session($host = null, $security = array() , $version = 1, $timeout = 10.0)
    {
        $this->host = $host;
        $this->security = $security;
        $this->version = $version;
        $this->timeout = $timeout;
        self::$conn = new MySNMPv2Conn();
        self::$conn->host = $host;
        self::$conn->security = $security;
        self::$conn->version = $version;
        self::$conn->timeout = $timeout;
    }
    public function changeHost($host = null){
      $this->host = $host;
      self::$conn->host = $host;
    }
    public function filter($mib = NULL)
    {
        if (empty($this->nodes))
        {
            return false;
        }
        $instance = new self($mib, $this->nodes);
        if ($this->host !== null && $this->version !== NULL && $this->security !== null)
        {
            $instance->snmp_session($this->host, $this->security, $this->version);
        }
        return $instance;
    }
    
    public function MIB($mib = null)
    {   
        $filename = null;
        $this->CallString = $mib;
        $this->OID = '.1.';
        $indexes = array();
        $arg = $mib;
        if(gettype($mib) === "array")
          {
            $mib = $arg[0];
            array_shift($arg);
            $indexes = $arg;
          }
        
        $_mib = explode("::", $mib);
        $mib = $_mib[0];
        $child = count($_mib) == 2 && count(explode('.', $_mib[1])) >= 2 ? explode('.', $_mib[1]) : array();
        if(count($child))
          {
            array_shift($child);
            $_mib[1] = explode('.', $_mib[1])[0];
          }
        $oid = count($_mib) >= 2 ? explode('.', $_mib[1])[0] : false;
        
        foreach($child as $choid)
          {
            $indexes[] = $choid;
          }
        //$child = (count($child) ? '.' . join('.', $child) : '');

        if (!isset($this->MIBS->{$mib}))
        {
            $filename = null;
            if (!file_exists(dirname(__FILE__) . "/mibs_compiled/$mib.data"))
            {
                if (file_exists(dirname(__FILE__) . "/mibs/$mib"))
                {
                    $filename = dirname(__FILE__) . "/mibs/$mib";
                }
                else if (file_exists(dirname(__FILE__) . "/mibs/$mib.mib"))
                {
                    $filename = dirname(__FILE__) . "/mibs/$mib.mib";
                }
                else if (file_exists(dirname(__FILE__) . "/mibs/$mib.txt"))
                {
                    $filename = dirname(__FILE__) . "/mibs/$mib.txt";
                }
                else
                {
                  $filename = $this->mibFileSearch(dirname(__FILE__) . "/mibs/", $mib);
                }
                
                if ($filename !== null)
                {
                    // compile mib file
                    $mc = new mib_compiler(true);
                    // imports
                    $mc->add_mib($filename, dirname(__FILE__) . "/mibs_compiled/$mib.data");
                    $mc->compile();
                }
            }
            if (file_exists(dirname(__FILE__) . "/mibs_compiled/$mib.data"))
            {
                $filename = dirname(__FILE__) . "/mibs_compiled/$mib.data";
                $this->MIBS->{$mib} = new MySNMPv2Object();
                $this->MIBS->{$mib} = $this->buildMIB(unserialize(file_get_contents($filename)), $name = "iso", $OID = '.1', $CallString = $this->CallString);
            }
            
            if($filename == null)
              {
                throw new \Exception('Missing MIB file ' . $mib);
              }
        }
        
        if(!$oid)
          {
            return $this->MIBS->{$mib};
          }
        else if(!count($indexes))
          {
            return $this->searchNode($this->MIBS->{$mib}, $oid);
          }
        else
          {
            $oid__ = $this->searchNode($this->MIBS->{$mib}, $oid);
            $oid__->OID = $oid__->OID . "." . implode("." , $indexes);
            return $oid__;
          }
        
    }
    
    public function setShortcut($key = null, $oid = null, $plain = false, $nodes = null)
    {
        if ($key !== null && $oid !== null)
        {
            if (!isset($this->shortcuts))
            {
                $this->shortcuts = new MySNMPv2Object();
            }
            $key_ = explode("::", $key);
            $tree = count($key_) > 1 ? $key_[0] : null;
            $key = count($key_) > 1 ? $key_[1] : $key;

            if ($tree !== null && !isset($this->{$tree}))
            {
                $this->{$tree} = new MySNMPv2Object();
            }
            if (!$plain)
            {
                $object = self::$mib->iso;
                foreach (explode(".", $oid) as $o)
                {
                    if (!isset($object->{$o}))
                    {
                        throw new \ErrorException("SNMP OID $o not found!");
                    }
                    $object = $object->{$o};
                }
            }
            else
            {
                $object = $this->OID($oid, $key, $nodes);
            }

            if (!empty($object) && !empty($key))
            {
                if ($tree !== null)
                {
                    @$this->{$tree}->{$key} = $object;
                }
                else
                {
                    @$this
                        ->shortcuts->{$key} = $object;
                }
            }
        }
    }
    final public function OID($oid = NULL, $name = NULL, $nodes = array())
    {
        return new MySNMPv2Object($oid, $name, $nodes, $oid);
    }

    final public function map()
    {
        return $this->mib;
    }
    final public function nodes()
    {
        return $this->nodes;
    }
    private function CleanOid(array &$data)
    {
      foreach($data as $k => &$v)
        {
          if($k === 'OID' && gettype($v) === 'array')
            {
              $v = $v[0];
            }
          else if(gettype($v) === 'array')
            {
              $this->CleanOid($v);
            }
        }
    }
    final public function GetCompiledTree()
    {
      $all = array();
      /**
       * Load All compiled MIBS
       */
      foreach(scandir(dirname(__FILE__) . "/mibs_compiled/") as $file)
        {
          if(explode(".", $file)[1] === 'data')
            {
              $mib = str_replace(".data", "", $file);
              $data = unserialize(file_get_contents(dirname(__FILE__) . "/mibs_compiled/" . $file));
              
              $all[$mib] = (array) $this->mapMIB($data, 'iso', '.1', $mib);
            }
        }
      /**
       * Merge MIBs to one tree
       */
      $oidTree = array();
      foreach($all as $MIB => $data)
        {
          $oidTree = array_merge_recursive($data, $oidTree);
        }
      $this->CleanOid($oidTree);
      
      return $oidTree;
    }
}

class MySNMPv2MapObject
{
  public $OID = NULL;
  public $MIB = null;
  function __construct($OID = NULL, $MIB = null)
    {

        if ($OID !== NULL)
        {
            $this->OID = $OID;
        }
        if ($MIB !== NULL)
        {
            $this->MIB = $MIB;
        }
    }
}

class MySNMPv2Object extends MySNMPv2
{
    public $OID = NULL;
    private $NAME = NULL;
    public $MIB = null;
    function __construct($OID = NULL, $NAME = NULL, $NODES = NULL, $MIB = null)
    {

        if ($OID !== NULL)
        {
            $this->OID = $this->fixOID($OID);
        }
        if ($NAME !== NULL)
        {
            $this->NAME = $NAME;
        }
        if ($NODES !== NULL)
        {
            $this->NODES = $NODES;
        }
        if ($MIB !== NULL)
        {
            $this->MIB = $MIB;
        }
    }
    private function fixOID($OID = '')
    {
        if (substr($OID, 0, 4) === 'iso.')
        {
            return str_replace('iso.', '.1.', $OID);
        }
        else
        {
            return $OID;
        }
    }
    final public function getIndexes($ndx = array(), $mode = 0)
      {
        $OID_ = $this->OID;
        $rsp = array();
        foreach($ndx as $n)
          {
            $this->OID = $OID_ . ".$n";
            $rsp[] = $this->get($mode);
          }
        
        return $rsp;
      }
    final public function iget($i = NULL)
      {
        $cst = '';
        if($i !== NULL)
          {
            switch(gettype($i))
              {
                case 'integer':
                  $cst .= '.' . $i;
                  break;
                case 'array':
                  foreach($i as $n)
                    {
                      $cst .= '.' . $n;
                    }
                  break;
              }
          }
        return $this->get(0, $cst);
      }
    public function get($mode = 0, $cust = NULL, $miboid = null) // 0 - only response, 1 - OID => response, 2 - TEXT_OID(if known) => response
    {
        $_OID = $cust == null ? $this->OID : $this->OID . $cust;
        
        if (parent::$conn->host === null)
        {
          trigger_error("No SNMP Instance. snmp_session(\$host, (array) \$security, \$snmpversion)", E_USER_WARNING);
        }
        
        global $tracyPanels;
        if($tracyPanels)
          {
            $tracyPanels->snmp->add(array(oid_format($_OID), $_OID), 'get', parent::$conn->host, parent::$conn->timeout, 'udp');
          }
        
        $snmp_socket = new snmp(parent::$conn->version, parent::$conn->timeout);
        $output = $snmp_socket->get(parent::$conn->host, $_OID, parent::$conn->security);
        if($tracyPanels)
          {
            $tracyPanels->snmp->end($output);
          }
        if(!isset($output[$_OID]))
          {
            return $output;
          }
        /*if ($output[$_OID] === "No such Instance" && substr($_OID, -1) !== '0')
        {
            $_OID .= ".0";
            $tracyPanels->snmp->add($_OID, 'get', parent::$conn->host, parent::$conn->timeout, 'udp');
            
            $output = $snmp_socket->get(parent::$conn->host, $_OID, parent::$conn->security);
            
            $tracyPanels->snmp->end($output);
        }*/
        $output = strpos(strtolower($output[$_OID]) , "no such") ? false : $output;
        switch ($mode)
        {
            case 0:
                return $output[$_OID];
            case 1:
                $r = new MySNMPv2OID();
                $r->{$_OID} = $output[$_OID];
                return $r;
            case 2:
                $r = new MySNMPv2OID();
                $r->{isset($this->NAME) ? $this->NAME : $_OID} = $output[$_OID];
                return $r;
        }
        return $response->_get();
    }
    
    final public function setInt($value = 0)
      {
        return $this->set('i', $value);
      }
    final public function setStr($value = "")
      {
        return $this->set('s', $value);
      }
    final public function setUns($value = 0)
      {
        return $this->set('u', $value);
      }
      
    public function set($type = 'i', $value = 0 )
    {
        //set($host, $target, $value=0, $type='i', $security=NULL)
        global $tracyPanels;
        if($tracyPanels)
          {
            $tracyPanels->snmp->add(array(oid_format($this->OID), $this->OID), 'set', parent::$conn->host, parent::$conn->timeout, 'udp');
          }
        $snmp_socket = new snmp(parent::$conn->version, parent::$conn->timeout);
        $out = $snmp_socket->set(parent::$conn->host, $this->OID, $value, $type, parent::$conn->security);
        if($tracyPanels)
          {
            $tracyPanels->snmp->end(json_encode($out));
          }
        return $out;
    }
    public function walk($i = null)
      {
        $cst = '';
        if($i !== NULL)
          {
            switch(gettype($i))
              {
                case 'integer':
                  $cst .= '.' . $i;
                  break;
                case 'array':
                  foreach($i as $n)
                    {
                      $cst .= '.' . $n;
                    }
                  break;
              }
          }
        global $tracyPanels;
        if($tracyPanels)
          {
            $tracyPanels->snmp->add(array(oid_format($this->OID.$cst), $this->OID.$cst), 'walk', parent::$conn->host, parent::$conn->timeout, 'udp');
          }
        $snmp_socket = new snmp(parent::$conn->version, parent::$conn->timeout);
        $out = $snmp_socket->walk(parent::$conn->host, $this->OID.$cst, parent::$conn->security);
        if($tracyPanels)
          {
            $tracyPanels->snmp->end(json_encode($out));
          }
        return $out;
      }
    public function walkArr($i = null)
      {
        $data = array();
        foreach($this->walk($i) as $oid => $val)
          {
            $data[] = $val;
          }
        
        return $data;
      }
    

    final public function getObjects()
      {
        global $tracyPanels;
        if (parent::$conn->host === null)
        {
            trigger_error("No SNMP Instance. snmp_session(\$host, (array) \$security, \$snmpversion)", E_USER_WARNING);
        }
        $keys = array();
        $args = func_get_args();
        if(func_num_args() == 1 && gettype($args[0]) == 'array')
          {
            $keys = $args[0];
          }
        else if(func_num_args() > 0)
          {
            foreach($args as $arg)
              {
                $keys[] = $arg;
              }
          }

        $table = new MySNMPv2Table();
        $snmp = new snmp(parent::$conn->version, parent::$conn->timeout);
        if (count($keys) && !isset($keys[0]))
        {
            $this->NODES = $keys;
        }
        else
        {
          foreach ($this->NODES ? : array() as $id => $name)
            {
                if(strpos($name, 'Index') !== false)
                  {
                    unset($this->NODES[$id]);
                  }
                
                foreach($keys as $ki => $kname)
                  {
                    if($kname == $name)
                      {
                        $keys[$ki] = $id;
                      }
                  }
            }
        }

        if (count($keys) && isset($keys[0]) && isset($this->NODES))
        {
            foreach ($this->NODES ? : array() as $id => $name)
            {
                if (!in_array($id, $keys))
                {
                    unset($this->NODES[$id]);
                }
            }
        }
        if (isset($this->NODES) && count($this->NODES))
        {
          foreach($this->NODES as $id => $name)
            {
              $o = $this->OID . '.' . $id . '.0';
              if($tracyPanels)
                {
                  $tracyPanels->snmp->add(array(oid_format($o), $o), 'get', parent::$conn->host, parent::$conn->timeout, 'udp');
                }
              $g = $snmp->get(parent::$conn->host, $o, parent::$conn->security);
              if($tracyPanels)
                {
                  $tracyPanels->snmp->end(json_encode($g[$o]));
                }
              $table->{$name} = $g[$o];
            }
        }
        return $table;
      }
    
    final public function assocTable()//$keys = array(), $filter = array()
      {
        $keys = array();
        $filter = array();
        $args = func_get_args();
        foreach($args as $i => $arg)
          {
            if(!$i && gettype($arg) == 'array')
              {
                $keys = $arg;
                $filter = func_num_args() == 2 ? $args[1] : array();
                break;
              }
            else if(gettype($arg) == 'string' || gettype($arg) == 'integer')
              {
                $keys[] = $arg;
              }
            else if(gettype($arg) == 'array')
              {
                $filter = $arg;
              }
          }
        return $this->table(3, $keys, $filter);
      }
    
    final public function listTable()
      {
        $keys = array();
        $filter = array();
        $args = func_get_args();
        foreach($args as $i => $arg)
          {
            if(!$i && gettype($arg) == 'array')
              {
                $keys = $arg;
                $filter = func_num_args() == 2 ? $args[1] : array();
                break;
              }
            else if(gettype($arg) == 'string' || gettype($arg) == 'integer')
              {
                $keys[] = $arg;
              }
            else if(gettype($arg) == 'array')
              {
                $filter = $arg;
              }
          }
        $response = array();
        
        $data = (array) $this->table(0, $keys, $filter);
        $dataKeys = array_keys($data);
        foreach($data["_indexes"] as $i => $n)
          {
            $item = new MySNMPv2Table();
            foreach($dataKeys as $key)
              {
                $item->{$key} = @$data[$key][$i] ?: null;
              }
            $item->index = $n;
            unset($item->_indexes);
            $response[] = $item;
          }
        
        return $response;
      }
      
    public function table($mode = 0, $keys = array(), $filter = array()) /* 0 - basic SNMP table, 2 - PHP rows, 2 - PHP assoc rows, 3 - object*/
    {
        global $tracyPanels;
        if (parent::$conn->host === null)
        {
            trigger_error("No SNMP Instance. snmp_session(\$host, (array) \$security, \$snmpversion)", E_USER_WARNING);
        }
        $indexes = array();
        $table = new MySNMPv2Table();
        $snmp = new snmp(parent::$conn->version, parent::$conn->timeout);
        $nodes = array();
        
        if (count($keys) && !isset($keys[0]))
        {
            $this->NODES = $keys;
        }
        else
        {
          foreach ($this->NODES ? : array() as $id => $name)
            {
                if(strpos($name, 'index') !== false)
                  {
                    unset($this->NODES[$id]);
                  }
                
                foreach($keys as $ki => $kname)
                  {
                    if($kname == $name)
                      {
                        $keys[$ki] = $id;
                      }
                  }
            }
        }

        if (count($keys) && isset($keys[0]) && isset($this->NODES))
        {
            foreach ($this->NODES ? : array() as $id => $name)
            {
                if (!in_array(gettype($keys[0]) !== 'string' ? $id : $name, $keys))
                {
                    unset($this->NODES[$id]);
                }
            }
        }

        if (isset($this->NODES))
        {
            if(!empty($filter)) // filter indexes by oid value
              {
                $filterID = 0;
                $filterValue = 0;
                $nodes = array_values($this->NODES);
                $revNodes = array();
                foreach($this->NODES as $id => $key)
                  {
                    $revNodes[$key] = $id;
                  }
                  
                foreach($filter as $id => $val)
                  {
                    $filterID = gettype($id) == 'string' ? (@$revNodes[$id] ?: 0) : $id;
                    $filterValue = $val;
                    break;
                  }
                // průvodní OID s filtrem...
                if($tracyPanels)
                  {
                    $tracyPanels->snmp->add(array(oid_format($this->OID . '.' . $filterID), $this->OID . '.' . $filterID), 'walk', parent::$conn->host, parent::$conn->timeout, 'udp');
                  }
                $walk = $snmp->walk(parent::$conn->host, $this->OID . '.' . $filterID, parent::$conn->security);
                
                if($tracyPanels)
                  {
                    $tracyPanels->snmp->end($walk);
                  }
                
                foreach($walk as $oid => $value)
                  {
                    $index  = intval(explode(".", $oid)[count(explode(".", $oid)) - 1]);
                    $key    = str_replace($this->OID . '.' . $filterID, "", $oid);
                    
                    if($value === $filterValue || (gettype($filterValue) == 'array' && in_array($value, $filterValue)))
                      {
                        
                        if (!isset($table->_indexes))
                          {
                              $table->_indexes = array();
                          }
                        if (!isset($table->_keys))
                          {
                              $table->_keys = array();
                          }
                        if (!isset($table->{$this->NODES[$filterID]}))
                          {
                            $table->{$this->NODES[$filterID]} = array();
                          }
                          
                          $table->_indexes[] = $index;
                          $table->_keys[] = $index;
                      }
                  }
                  // dotažení zbytku 
                  foreach ($this->NODES as $id => $name)
                    {
                      if($id !== $filterID)
                        {
                          $table->{$name} = array();
                        }
                      foreach(@$table->_indexes ?: array() as $i => $index)
                        {
                          $theOID = $this->OID . '.' . $id . '.' . $index;
                          $value = $snmp->get(parent::$conn->host, $theOID, parent::$conn->security);
                          if(isset($value[$theOID]))
                            {
                              $table->{$name}[] = $value[$theOID];
                            }
                        }
                    }
                  
              }
            else
              {
                foreach ($this->NODES as $id => $name)
                {
                    $nodes[] = $name;
                    if($tracyPanels)
                      {
                        $tracyPanels->snmp->add(array(oid_format($this->OID . '.' . $id), $this->OID . '.' . $id), 'walk', parent::$conn->host, parent::$conn->timeout, 'udp');
                      }
                    $node_response = $snmp->walk(parent::$conn->host, $this->OID . '.' . $id, parent::$conn->security);
                    if($tracyPanels)
                      {
                        $tracyPanels->snmp->end($node_response);
                      }
                    $table->{$name} = array();
                    foreach ($node_response as $oid => $value)
                    {
                        $index  = intval(explode(".", $oid)[count(explode(".", $oid)) - 1]);
                        $key    = str_replace($this->OID . '.' . $id . '.', "", $oid);

                        
                        if (!isset($table->_indexes))
                          {
                              $table->_indexes = array();
                          }
                        if (!isset($table->_keys))
                          {
                              $table->_keys = array();
                          }
    
                        if (!in_array($index, $table->_indexes))
                        {
                            $table->_indexes[] = $index;
                        }
                        
                        if (!in_array($key, $table->_keys))
                        {
                            $table->_keys[] = $key;
                        }
                        
                        $table->{$name}[] = $value;
                    }
                }
              }
            
        }
        
        if(!count($nodes))
          {
            return $table;
          }
        if(!$mode)
          {
            return $table;
          }
        else
          {
            $array = array();
            foreach (@$table->{$nodes[0]} ?: array() as $i => $fn)
            {
                $row = $mode == 1 ? array(
                    $fn
                ) : array(
                    'index' => isset($table->_indexes[$i]) ? $table->_indexes[$i] : 0,
                    'key' => isset($table->_keys[$i]) ? $table->_keys[$i] : 0,
                    $nodes[0] => $fn
                );
                foreach ($nodes as $n => $node)
                {
                    if ($n > 0)
                    {
                        if ($mode == 1)
                        {
                            @$row[] = $table->{$node}[$i];
                        }
                        else
                        {
                            @$row[$node] = $table->{$node}[$i];
                        }
                    }
                }
                if ($mode == 1)
                {
                    $array[$table->_indexes[$i]] = $row;
                }
                else
                {
                    $array[] = $row;
                }
            }
            if($mode == 3)
              {
                $objectArray = array();
                foreach($array as $row)
                  {
                    $oRow = new MySNMPv2Table();
                    foreach($row as $k => $v)
                      {
                        $oRow->{$k} = $v;
                      }
                    $objectArray[] = $oRow;
                  }
                $array = $objectArray;
              }
            return $array; 
          }

        return $table;
    }
}

