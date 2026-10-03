/* eslint-disable max-len */
// flexiWAN SD-WAN software - flexiEdge, flexiManage.
// For more information go to https://flexiwan.com
// Copyright (C) 2019  flexiWAN Ltd.

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.

// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

const { ObjectId } = require('mongoose').Types;
const { validateDevice, validateModifyDeviceMsg, validateStaticRoute } = require('../validators');
const { validateConfiguration } = require('../../utils/deviceUtils');
const maxMetric = 2 * 10 ** 9;
const { devices } = require('../../models/devices');

let deviceResponse = [];
// let expectedQuery = {};

const setResponse = (response) => {
  deviceResponse = response;
};

beforeAll(async () => {
  // Override organizations aggregate
  delete devices.aggregate;
  devices.aggregate = function () {
    // expect(query).toEqual(expectedQuery);
    return deviceResponse;
  };
  module.exports = devices;

  // setQuery({
  //   _id: {
  //     $in: [
  //       ObjectId('5ef0b7a657344d1ad6187100'),
  //       ObjectId('5ef0b7a657344d1ad6187101'),
  //       ObjectId('5ef0b7a657344d1ad6187102')
  //     ]
  //   },
  //   group: 'Default'
  // }, [
  //   ObjectId('5ef0b7a657344d1ad6187100'), ObjectId('5ef0b7a657344d1ad6187101')
  // ]);
});

describe('validateDevice', () => {
  let device;
  const org = {
    tunnelRange: '10.100.0.0',
    vxlanPort: '4789'
  };
  const successObject = {
    valid: true,
    err: ''
  };
  const failureObject = {
    valid: false,
    err: ''
  };

  beforeEach(() => {
    setResponse([]);

    device = {
      org: {
        tunnelRange: '10.100.0.0'
      },
      bgp: {
        neighbors: []
      },
      versions: {
        agent: '6.0.1'
      },
      interfaces: [{
        name: 'eth0',
        devId: '00:02.00',
        driver: 'igb-1000',
        MAC: 'ab:45:90:ed:89:16',
        dhcp: 'no',
        IPv4: '192.168.100.1',
        IPv4Mask: '24',
        IPv6: '2001:db8:85a3:8d3:1319:8a2e:370:7348',
        IPv6Mask: '64',
        PublicIP: '72.168.10.30',
        PublicPort: '4789',
        NatType: '',
        useStun: true,
        gateway: '',
        metric: '',
        isAssigned: true,
        routing: 'OSPF',
        type: 'LAN',
        pathlabels: []
      },
      {
        name: 'eth1',
        devId: '00:02.01',
        driver: 'igb-1000',
        MAC: 'ab:45:90:ed:89:17',
        dhcp: 'no',
        IPv4: '172.23.100.1',
        IPv4Mask: '24',
        IPv6: '2001:db8:85a3:8d3:1319:8a2e:370:7346',
        IPv6Mask: '64',
        PublicIP: '172.23.100.1',
        PublicPort: '4789',
        NatType: '',
        useStun: true,
        gateway: '172.23.100.10',
        metric: '0',
        isAssigned: true,
        routing: 'None',
        type: 'WAN',
        pathlabels: [ObjectId('5e65290fbe66a2335718e081')]
      },
      {
        name: 'eth2',
        devId: '00:03.00',
        driver: 'igb-1000',
        MAC: 'ab:45:90:ed:89:17',
        dhcp: 'no',
        IPv4: '192.168.105.1',
        IPv4Mask: '24',
        IPv6: '2001:db8:85a3:8d3:1319:8a2e:370:7349',
        IPv6Mask: '64',
        PublicIP: '72.168.10.56',
        PublicPort: '4789',
        NatType: '',
        useStun: true,
        gateway: '',
        metric: '',
        isAssigned: false,
        routing: 'OSPF',
        type: 'LAN',
        pathlabels: []
      }]
    };
  });

  // Happy path
  it('Should be a valid device', async () => {
    const result = await validateDevice(device, org);
    expect(result).toMatchObject(successObject);
  });

  it('Should ignore unassigned interfaces', async () => {
    device.interfaces.push({
      name: 'eth0',
      devId: '00:02.01',
      driver: 'igb-1000',
      MAC: 'ab:45:90:ed:89:17',
      dhcp: 'invalid-dhcp',
      IPv4: 'invalid-IPv4',
      IPv4Mask: 'invalid-mask',
      IPv6: 'invalid-IPv6',
      IPv6Mask: 'invalid-mask',
      isAssigned: false,
      routing: 'None',
      type: 'invalid-type'
    });
    const result = await validateDevice(device, org);
    expect(result).toMatchObject(successObject);
  });

  it('Should be an invalid device if it has zero assigned LAN interfaces', async () => {
    device.interfaces[0].type = 'Not-LAN';
    failureObject.err = 'There should be at least one LAN and one WAN interfaces';
    const result = await validateDevice(device, org, true);
    expect(result).toMatchObject(failureObject);
  });

  it('Should be an invalid device if it has zero assigned WAN interfaces', async () => {
    device.interfaces[1].type = 'Not-WAN';
    failureObject.err = 'There should be at least one LAN and one WAN interfaces';
    const result = await validateDevice(device, org, true);
    expect(result).toMatchObject(failureObject);
  });

  it('Should be an invalid device if LAN IPv4 address is null', async () => {
    device.interfaces[0].IPv4 = null;
    failureObject.err = `[${device.interfaces[0].name}]: Interface does not have an IPv4 address`;
    const result = await validateDevice(device, org);
    expect(result).toMatchObject(failureObject);
  });

  it('Should be an invalid device if LAN IPv4 address is empty', async () => {
    device.interfaces[0].IPv4 = '';
    failureObject.err = `[${device.interfaces[0].name}]: Interface does not have an IPv4 address`;
    const result = await validateDevice(device, org);
    expect(result).toMatchObject(failureObject);
  });

  it('Should be an invalid device if LAN IPv4 mask is empty', async () => {
    device.interfaces[0].IPv4Mask = '';
    failureObject.err = `[${device.interfaces[0].name}]: Interface does not have an IPv4 mask`;
    const result = await validateDevice(device, org);
    expect(result).toMatchObject(failureObject);
  });

  it('Should be an invalid device if both LAN IPv4 address and mask are empty', async () => {
    device.interfaces[0].IPv4 = '';
    device.interfaces[0].IPv4Mask = '';
    failureObject.err = `[${device.interfaces[0].name}]: Interface does not have an IPv4 address`;
    const result = await validateDevice(device, org);
    expect(result).toMatchObject(failureObject);
  });

  it('Should be an invalid device if LAN IPv4 address ends with .0', async () => {
    device.interfaces[0].IPv4 = '192.168.111.0';
    device.interfaces[0].IPv4Mask = '24';
    failureObject.err = `[${device.interfaces[0].name}]: ` +
    'IP (192.168.111.0/24) cannot be Local or Broadcast address';
    const result = await validateDevice(device, org);
    expect(result).toMatchObject(failureObject);
  });

  it('Should be an invalid device if LAN IPv4 address ends with .255', async () => {
    device.interfaces[0].IPv4 = '192.168.111.255';
    device.interfaces[0].IPv4Mask = '24';
    failureObject.err = `[${device.interfaces[0].name}]: ` +
    'IP (192.168.111.255/24) cannot be Local or Broadcast address';
    const result = await validateDevice(device, org);
    expect(result).toMatchObject(failureObject);
  });

  it('Should be a valid device if valid IP address is set on interface', async () => {
    device.interfaces[1].IPv4 = '95.217.233.255';
    device.interfaces[1].IPv4Mask = '15';
    const result = await validateDevice(device, org);
    expect(result).toMatchObject(successObject);
  });

  it('Should be an invalid device if broadcast address is set on interface', async () => {
    device.interfaces[1].IPv4 = '95.217.255.255';
    device.interfaces[1].IPv4Mask = '15';
    failureObject.err = `[${device.interfaces[1].name}]: ` +
    'IP (95.217.255.255/15) cannot be Local or Broadcast address';
    const result = await validateDevice(device, org);
    expect(result).toMatchObject(failureObject);
  });

  it('Should be an invalid device if network address is set on interface', async () => {
    device.interfaces[1].IPv4 = '95.216.0.0';
    device.interfaces[1].IPv4Mask = '15';
    failureObject.err = `[${device.interfaces[1].name}]: ` +
    'IP (95.216.0.0/15) cannot be Local or Broadcast address';
    const result = await validateDevice(device, org);
    expect(result).toMatchObject(failureObject);
  });

  it('Should be a valid device if network/broadcast with /31 mask is set on interface', async () => {
    device.interfaces[0].IPv4 = '197.234.116.204';
    device.interfaces[0].IPv4Mask = '31';
    device.interfaces[1].IPv4 = '197.234.117.205';
    device.interfaces[1].IPv4Mask = '31';
    const result = await validateDevice(device, org);
    expect(result).toMatchObject(successObject);
  });

  it('Should be an invalid device if Public IP has an overlap with another WAN interface', async () => {
    device.interfaces[0].IPv4 = '192.168.1.1';
    device.interfaces[0].IPv4Mask = '24';
    device.interfaces[0].PublicIP = '1.1.1.1';
    device.interfaces[0].gateway = '192.168.1.2';
    device.interfaces[0].routing = '';
    device.interfaces[0].type = 'WAN';
    device.interfaces[1].IPv4 = '1.1.1.1';
    device.interfaces[1].IPv4Mask = '32';
    failureObject.err = `IP address of [${device.interfaces[1].name}]` +
      ` has an overlap with Public IP of [${device.interfaces[0].name}]`;
    const result = await validateDevice(device, org);
    expect(result).toMatchObject(failureObject);
  });

  it('Should be an invalid device if WAN IPv4 address is null', async () => {
    device.interfaces[0].IPv4 = null;
    failureObject.err = `[${device.interfaces[0].name}]: Interface does not have an IPv4 address`;
    const result = await validateDevice(device, org);
    expect(result).toMatchObject(failureObject);
  });

  it('Should be an invalid device if WAN IPv4 address is empty', async () => {
    device.interfaces[0].IPv4 = '';
    failureObject.err = `[${device.interfaces[0].name}]: Interface does not have an IPv4 address`;
    const result = await validateDevice(device, org);
    expect(result).toMatchObject(failureObject);
  });

  it('Should be an invalid device if WAN IPv4 mask is empty', async () => {
    device.interfaces[0].IPv4Mask = '';
    failureObject.err = `[${device.interfaces[0].name}]: Interface does not have an IPv4 mask`;
    const result = await validateDevice(device, org);
    expect(result).toMatchObject(failureObject);
  });

  it('Should be an invalid device if both WAN IPv4 address and mask are empty', async () => {
    device.interfaces[0].IPv4 = '';
    device.interfaces[0].IPv4Mask = '';
    failureObject.err = `[${device.interfaces[0].name}]: Interface does not have an IPv4 address`;
    const result = await validateDevice(device, org);
    expect(result).toMatchObject(failureObject);
  });

  it('Should be an invalid device if assigned interfaces are on the same subnet', async () => {
    device.interfaces[0].IPv4 = '10.0.0.1';
    device.interfaces[1].IPv4 = '10.0.0.2';
    failureObject.err = 'IP addresses of the assigned interfaces have an overlap';
    const result = await validateDevice(device, org);
    expect(result).toMatchObject(failureObject);
  });

  it('Should be an invalid device if LAN and WAN have the same ip', async () => {
    device.interfaces[0].IPv4 = '10.0.0.1';
    device.interfaces[1].IPv4 = '10.0.0.1';
    failureObject.err = 'IP addresses of the assigned interfaces have an overlap';
    const result = await validateDevice(device, org);
    expect(result).toMatchObject(failureObject);
  });

  it('Should be a valid device if LAN assigned interfaces have the same ip', async () => {
    device.interfaces[0].IPv4 = '10.0.0.1';
    device.interfaces[2].IPv4 = '10.0.0.1';
    device.interfaces[2].isAssigned = true;
    const result = await validateDevice(device, org);
    expect(result).toMatchObject(successObject);
  });

  it('Should be an invalid device if LAN assigned interfaces have overlapping', async () => {
    device.interfaces[0].IPv4 = '10.0.0.1';
    device.interfaces[2].IPv4 = '10.0.0.2';
    device.interfaces[2].isAssigned = true;
    failureObject.err = 'IP addresses of the assigned interfaces have an overlap';
    const result = await validateDevice(device, org);
    expect(result).toMatchObject(failureObject);
  });

  it('Should be a valid device if WAN and default GW IP addresses are not on the same subnet',
    async () => {
      device.interfaces[1].IPv4 = '10.0.0.2';
      // failureObject.err = 'WAN and default route IP addresses are not on the same subnet';
      const result = await validateDevice(device, org);
      expect(result).toMatchObject(successObject);
    });

  it('Should be an invalid device if OSPF is configured on the WAN interface', async () => {
    device.interfaces[1].routing = 'OSPF';
    failureObject.err = 'OSPF should not be configured on WAN interface';
    const result = await validateDevice(device, org);
    expect(result).toMatchObject(failureObject);
  });

  it('Should be an invalid device if it has a LAN subnets overlap with other devices', async () => {
    device.name = 'Device 1';
    device._id = '123456';

    const deviceSubnet = `${device.interfaces[0].IPv4}/${device.interfaces[0].IPv4Mask}`;

    // simulate response of the "checkLanOverlappingWith" function
    const dbReply = {
      _id: 1,
      deviceName: 'deviceName2',
      interfaceName: 'eth3',
      interfaceDevId: 'pci:test_dev_id',
      interfaceSubnet: '192.168.100.3/24',
      isOverlappingWith: deviceSubnet
    };
    setResponse([dbReply]);

    failureObject.err =
    `The interface network ${deviceSubnet} overlaps with address ${dbReply.interfaceSubnet} of the LAN interface ${dbReply.interfaceName} in device ${dbReply.deviceName}`;

    const result = await validateDevice(device, org, true, false);
    expect(result).toMatchObject(failureObject);

    // now check when "allowOverlapping" is true
    const resultWithAllow = await validateDevice(device, org, true, true);
    expect(resultWithAllow).toMatchObject(successObject);
  });

  it('Should be an invalid device if it has a LAN subnets overlap tunnel dedicated network', async () => {
    device.name = 'Device 1';
    device._id = '123456';
    device.interfaces[0].IPv4 = '10.100.0.1';
    device.interfaces[0].IPv4Mask = '24';

    const deviceSubnet = '10.100.0.1/24';
    failureObject.err =
    // eslint-disable-next-line max-len
    `The interface network ${deviceSubnet} overlaps with flexiWAN tunnel range (10.100.0.0/16)`;

    const result = await validateDevice(device, org, true, false);
    expect(result).toMatchObject(failureObject);
  });

  it('Should be an invalid device if WAN interface is not assigned a GW', async () => {
    delete device.interfaces[1].gateway;
    failureObject.err = 'All WAN interfaces should be assigned a default GW';
    const result = await validateDevice(device, org);
    expect(result).toMatchObject(failureObject);
  });

  it('Should be an invalid device if WAN interface\'s GW is invalid', async () => {
    device.interfaces[1].gateway = 'invalid-ip-address';
    failureObject.err = 'All WAN interfaces should be assigned a default GW';
    const result = await validateDevice(device, org);
    expect(result).toMatchObject(failureObject);
  });

  it('Should be an invalid device if LAN interface is assigned a GW', async () => {
    device.interfaces[0].gateway = '10.0.0.100';
    failureObject.err = 'LAN interfaces should not be assigned a default GW';
    const result = await validateDevice(device, org);
    expect(result).toMatchObject(failureObject);
  });

  it('Should be an invalid device if LAN interface has path labels', async () => {
    device.interfaces[0].pathlabels = [ObjectId('5e65290fbe66a2335718e081')];
    failureObject.err = 'Path Labels are not allowed on LAN interfaces';
    const result = await validateDevice(device, org);
    expect(result).toMatchObject(failureObject);
  });

  it('Should be an invalid device if metric is higher than maxMetric', async () => {
    device.interfaces[1].metric = maxMetric + 1;
    failureObject.err = `Metric should be lower than ${maxMetric}`;
    const result = await validateDevice(device, org);
    expect(result).toMatchObject(failureObject);
  });

  it('Should be an invalid device if metric on WAN VPP interfaces is duplicated', async () => {
    device.interfaces[0].pathlabels = [];
    device.interfaces.push({
      name: 'eth2',
      devId: '00:03.01',
      driver: 'igb-1000',
      MAC: 'ab:45:90:ed:89:18',
      dhcp: 'no',
      IPv4: '172.23.102.1',
      IPv4Mask: '24',
      PublicIP: '172.23.102.1',
      PublicPort: '4789',
      NatType: '',
      useStun: true,
      gateway: '172.23.102.10',
      metric: '',
      isAssigned: true,
      routing: 'None',
      type: 'WAN',
      pathlabels: []
    });
    failureObject.err = 'Duplicated metrics are not allowed on WAN interfaces';
    const result = await validateDevice(device, org);
    expect(result).toMatchObject(failureObject);
  });

  it('Should be an invalid device if interfaces are not of the array type', async () => {
    device.interfaces = null;
    failureObject.err = 'There should be at least two interfaces';
    const result = await validateDevice(device, org);
    expect(result).toMatchObject(failureObject);
  });
});

describe('validateModifyDeviceMsg', () => {
  let modifyDevMsg;
  const successObject = {
    valid: true,
    err: ''
  };
  const failureObject = {
    valid: false,
    err: ''
  };

  beforeEach(() => {
    modifyDevMsg = [
      {
        pci: '0000:00:03.00',
        addr: '10.0.0.101/24',
        addr6: 'fe80::a00:27ff:fe8d:fbbc/64',
        routing: 'NONE',
        type: 'WAN'
      },
      {
        pci: '0000:00:08.00',
        addr: '192.168.56.100/24',
        addr6: 'fe80::a00:27ff:fe8d:fbbc/64',
        routing: 'OSPF',
        type: 'LAN'
      }
    ];
  });

  // Happy path
  // Single interface
  it('Should be a valid message', () => {
    const result = validateModifyDeviceMsg(modifyDevMsg);
    expect(result).toMatchObject(successObject);
  });

  // Array of interfaces
  it('Should be a valid if message contains a single interface', () => {
    const singleIfc = {
      pci: '0000:00:03.00',
      addr: '10.0.0.101/24',
      addr6: 'fe80::a00:27ff:fe8d:fbbc/64',
      routing: 'NONE',
      type: 'WAN'
    };
    const result = validateModifyDeviceMsg(singleIfc);
    expect(result).toMatchObject(successObject);
  });

  // Empty array
  it('Should be a valid message contains no interfaces', () => {
    const emptyArray = [];
    const result = validateModifyDeviceMsg(emptyArray);
    expect(result).toMatchObject(successObject);
  });

  it('Should be an invalid message if IPv4 address contains double /', () => {
    modifyDevMsg[0].addr = '10.0.0.1//24';
    failureObject.err = 'Bad request: Interface does not have an IPv4 mask';
    const result = validateModifyDeviceMsg(modifyDevMsg);
    expect(result).toMatchObject(failureObject);
  });

  it('Should be an invalid message if IPv4 address is missing', () => {
    modifyDevMsg[0].addr = '/24';
    failureObject.err = 'Bad request: Interface does not have an IPv4 address';
    const result = validateModifyDeviceMsg(modifyDevMsg);
    expect(result).toMatchObject(failureObject);
  });

  it('Should be an invalid message if IPv4 mask is missing', () => {
    modifyDevMsg[0].addr = '10.0.0.1';
    failureObject.err = 'Bad request: Interface does not have an IPv4 mask';
    const result = validateModifyDeviceMsg(modifyDevMsg);
    expect(result).toMatchObject(failureObject);
  });

  it('Should be an invalid message if both IPv4 address and mask are missing', () => {
    modifyDevMsg[0].addr = null;
    failureObject.err = 'Bad request: Interface does not have an IPv4 address';
    const result = validateModifyDeviceMsg(modifyDevMsg);
    expect(result).toMatchObject(failureObject);
  });

  it('Should be an invalid message if IPv4 address is invalid', () => {
    modifyDevMsg[0].addr = '10.0.0./24';
    failureObject.err = `Bad request: IPv4 address ${modifyDevMsg[0].addr} is not valid`;
    const result = validateModifyDeviceMsg(modifyDevMsg);
    expect(result).toMatchObject(failureObject);
  });

  it('Should be an invalid message if IPv4 mask is invalid', () => {
    modifyDevMsg[0].addr = '10.0.0.1/123';
    failureObject.err = `Bad request: IPv4 mask ${modifyDevMsg[0].addr} is not valid`;
    const result = validateModifyDeviceMsg(modifyDevMsg);
    expect(result).toMatchObject(failureObject);
  });

  it('Should be an invalid message if both IPv4 address and mask are invalid', () => {
    modifyDevMsg[0].addr = '10.0.0./345';
    failureObject.err = `Bad request: IPv4 address ${modifyDevMsg[0].addr} is not valid`;
    const result = validateModifyDeviceMsg(modifyDevMsg);
    expect(result).toMatchObject(failureObject);
  });

  it('Should be an invalid message if one of the interfaces is invalid', () => {
    modifyDevMsg[1].addr = '';
    failureObject.err = 'Bad request: Interface does not have an IPv4 address';
    const result = validateModifyDeviceMsg(modifyDevMsg);
    expect(result).toMatchObject(failureObject);
  });
});

describe('validateLteInterfaceConfiguration', () => {
  let intf;
  let configuration;
  const successObject = {
    valid: true,
    err: ''
  };
  const failureObject = {
    valid: false,
    err: ''
  };

  beforeEach(() => {
    intf = {
      deviceType: 'lte'
    };
    configuration = {
      apn: 'test_apn',
      enable: true
    };
  });

  it('Should be a valid lte configuration', () => {
    const result = validateConfiguration(intf, configuration);
    expect(result).toMatchObject(successObject);
  });

  it('Should be an invalid lte configuration - missed enable', () => {
    delete configuration.enable;
    failureObject.err = '"enable" is required';
    const result = validateConfiguration(intf, configuration);
    expect(result).toMatchObject(failureObject);
  });

  it('Should be an invalid lte configuration - missed apn', () => {
    delete configuration.apn;
    failureObject.err = '"apn" is required';
    const result = validateConfiguration(intf, configuration);
    expect(result).toMatchObject(failureObject);
  });

  it('Should be an invalid lte configuration - auth not supported', () => {
    configuration.auth = 'TEST';
    failureObject.err = '"auth" must be one of [MSCHAPV2, PAP, CHAP, null, ]';
    const result = validateConfiguration(intf, configuration);
    expect(result).toMatchObject(failureObject);
  });
});

describe('validateWiFiInterfaceConfiguration', () => {
  let intf;
  let configuration;
  const successObject = {
    valid: true,
    err: ''
  };
  const failureObject = {
    valid: false,
    err: ''
  };

  beforeEach(() => {
    intf = {
      deviceType: 'wifi'
    };
    configuration = {
      '2.4GHz': {
        ssid: 'wifi_band_2.4',
        enable: true,
        channel: '0',
        bandwidth: '20',
        hideSsid: false,
        encryption: 'aes-ccmp',
        operationMode: 'n',
        securityMode: 'wpa2-psk',
        password: 'wifi_band_2_pass',
        region: 'US'
      },
      '5GHz': {
        ssid: 'wifi_band_5',
        enable: true,
        channel: '0',
        bandwidth: '20',
        hideSsid: false,
        encryption: 'aes-ccmp',
        operationMode: 'ac',
        securityMode: 'wpa2-psk',
        password: 'wifi_band_2_pass',
        region: 'US'
      }
    };
  });

  it('Should be a valid wifi configuration  - two bands', () => {
    const result = validateConfiguration(intf, configuration);
    expect(result).toMatchObject(successObject);
  });

  it('Should be a valid wifi configuration - 2.4GHz', () => {
    delete configuration['5GHz'];
    const result = validateConfiguration(intf, configuration);
    expect(result).toMatchObject(successObject);
  });

  it('Should be a valid wifi configuration - 5GHz', () => {
    delete configuration['2.4GHz'];
    const result = validateConfiguration(intf, configuration);
    expect(result).toMatchObject(successObject);
  });

  it('Should be a valid wifi configuration - 5GHz', () => {
    delete configuration['2.4GHz'];
    delete configuration['5Ghz'];
    const result = validateConfiguration(intf, configuration);
    expect(result).toMatchObject(successObject);
  });

  it('Should be an invalid configuration - wrong securityMode is not allowed when enabled', () => {
    configuration['2.4GHz'].securityMode = 'test';
    failureObject.err = '"2.4GHz.securityMode" must be one of [open, wpa-psk, wpa2-psk]';
    const result = validateConfiguration(intf, configuration);
    expect(result).toMatchObject(failureObject);
  });

  it('Should be an invalid configuration - empty securityMode is not allowed when enabled', () => {
    configuration['2.4GHz'].securityMode = '';
    failureObject.err = '"2.4GHz.securityMode" must be one of [open, wpa-psk, wpa2-psk]';
    const result = validateConfiguration(intf, configuration);
    expect(result).toMatchObject(failureObject);
  });

  it('Should be a valid wifi configuration - missed securityMode allowed when disabled', () => {
    configuration['2.4GHz'].securityMode = '';
    configuration['2.4GHz'].enable = false;
    const result = validateConfiguration(intf, configuration);
    expect(result).toMatchObject(successObject);
  });

  it('Should be an invalid wifi configuration - not supported country code', () => {
    configuration['2.4GHz'].region = 'GG';
    failureObject.err = 'Region GG is not valid';
    const result = validateConfiguration(intf, configuration);
    expect(result).toMatchObject(failureObject);
  });

  it('Should be an invalid wifi configuration - channel not valid', () => {
    configuration['2.4GHz'].channel = 'test';
    failureObject.err = 'test is not a valid channel number';
    const result = validateConfiguration(intf, configuration);
    expect(result).toMatchObject(failureObject);
  });

  it('Should be an invalid wifi configuration - channel not valid', () => {
    configuration['2.4GHz'].channel = '-2';
    failureObject.err = '-2 is not a valid channel number';
    const result = validateConfiguration(intf, configuration);
    expect(result).toMatchObject(failureObject);
  });

  it('Should be an invalid wifi configuration - channel not valid', () => {
    configuration['2.4GHz'].channel = '12';
    configuration['2.4GHz'].region = 'US';
    failureObject.err = 'Channel must be between 0 to 11';
    const result = validateConfiguration(intf, configuration);
    expect(result).toMatchObject(failureObject);
  });

  it('Should be a valid wifi configuration', () => {
    configuration['2.4GHz'].channel = '12';
    configuration['2.4GHz'].region = 'DE';
    const result = validateConfiguration(intf, configuration);
    expect(result).toMatchObject(successObject);
  });

  it('Should be an invalid wifi configuration - channel not valid', () => {
    configuration['2.4GHz'].channel = '14';
    configuration['2.4GHz'].region = 'DE';
    failureObject.err = 'Channel must be between 0 to 13';
    const result = validateConfiguration(intf, configuration);
    expect(result).toMatchObject(failureObject);
  });

  it('Should be an invalid wifi configuration - channel not valid', () => {
    configuration['5GHz'].channel = '14';
    failureObject.err = 'Channel 14 is not valid number for country US';
    const result = validateConfiguration(intf, configuration);
    expect(result).toMatchObject(failureObject);
  });

  it('Should be a valid wifi configuration', () => {
    configuration['5GHz'].channel = '153';
    const result = validateConfiguration(intf, configuration);
    expect(result).toMatchObject(successObject);
  });

  it('Should be an invalid wifi region', () => {
    configuration['5GHz'].channel = '110';
    configuration['5GHz'].region = 'RU';
    failureObject.err = 'Region RU is not valid';
    const result = validateConfiguration(intf, configuration);
    expect(result).toMatchObject(failureObject);
  });

  it('Should be an invalid wifi configuration', () => {
    configuration['5GHz'].channel = '110';
    configuration['5GHz'].region = 'NO';
    failureObject.err = 'Channel 110 is not valid number for country NO';
    const result = validateConfiguration(intf, configuration);
    expect(result).toMatchObject(failureObject);
  });
});

describe('validateStaticRoute', () => {
  let device;
  let route;
  const tunnels = [{ num: 2 }];

  const successObject = {
    valid: true,
    err: ''
  };
  const failureObject = {
    valid: false,
    err: ''
  };

  beforeEach(() => {
    route = {
      destination: '1.1.1.1',
      gateway: '192.168.100.2',
      ifname: 'pci:0000:00:01.00',
      metric: '10'
    };

    device = {
      org: {
        tunnelRange: '10.100.0.0'
      },
      interfaces: [{
        name: 'eth0',
        devId: 'pci:0000:00:01.00',
        driver: 'igb-1000',
        MAC: 'ab:45:90:ed:89:16',
        dhcp: 'no',
        IPv4: '192.168.100.1',
        IPv4Mask: '24',
        IPv6: '2001:db8:85a3:8d3:1319:8a2e:370:7348',
        IPv6Mask: '64',
        PublicIP: '72.168.10.30',
        PublicPort: '4789',
        NatType: '',
        useStun: true,
        gateway: '',
        metric: '',
        isAssigned: true,
        routing: 'OSPF',
        type: 'LAN',
        pathlabels: []
      },
      {
        name: 'eth1',
        devId: 'pci:0000:00:02.00',
        driver: 'igb-1000',
        MAC: 'ab:45:90:ed:89:17',
        dhcp: 'no',
        IPv4: '172.23.100.1',
        IPv4Mask: '24',
        IPv6: '2001:db8:85a3:8d3:1319:8a2e:370:7346',
        IPv6Mask: '64',
        PublicIP: '172.23.100.1',
        PublicPort: '4789',
        NatType: '',
        useStun: true,
        gateway: '172.23.100.10',
        metric: '0',
        isAssigned: true,
        routing: 'None',
        type: 'WAN',
        pathlabels: [ObjectId('5e65290fbe66a2335718e081')]
      }]
    };
  });

  // Happy path
  it('Should be valid if route gateway on the same subnet with interface', () => {
    const result = validateStaticRoute(device, tunnels, route);
    expect(result).toMatchObject(successObject);
  });

  it('Should be valid if route gateway match tunnel loopback interface IP', () => {
    route.gateway = '10.100.0.6';
    route.ifname = '';
    const result = validateStaticRoute(device, tunnels, route);
    expect(result).toMatchObject(successObject);
  });

  it('Should be an invalid static route config if gateway is not provided', () => {
    route.gateway = '';
    failureObject.err = 'Gateway is required in a static route';
    const result = validateStaticRoute(device, tunnels, route);
    expect(result).toMatchObject(failureObject);
  });

  it('Should be an invalid static route config if destination is not provided', () => {
    route.destination = '';
    failureObject.err = 'Destination is required in a static route';
    const result = validateStaticRoute(device, tunnels, route);
    expect(result).toMatchObject(failureObject);
  });

  it('Should be an invalid static route config if unknown interface used', () => {
    route.ifname = 'pci:0000:00:03.00';
    failureObject.err = `Static route interface not found '${route.ifname}'`;
    const result = validateStaticRoute(device, tunnels, route);
    expect(result).toMatchObject(failureObject);
  });

  it('Should be an invalid route if interface IP and gateway not on the same subnet', () => {
    const ifc = device.interfaces[0];
    route.ifname = 'pci:0000:00:01.00';
    route.gateway = '192.168.101.1';
    failureObject.err =
      `Interface IP ${ifc.IPv4} and gateway ${route.gateway} are not on the same subnet`;
    const result = validateStaticRoute(device, tunnels, route);
    expect(result).toMatchObject(failureObject);
  });

  // eslint-disable-next-line max-len
  it('Should be a valid route if interface IP and gateway not on the same subnet but "onlink" enabled', () => {
    route.ifname = 'pci:0000:00:01.00';
    route.gateway = '192.168.101.1';
    route.onLink = true;
    const result = validateStaticRoute(device, tunnels, route);
    expect(result).toMatchObject(successObject);
  });

  it('Should be an invalid route if interface IP and gateway not on the same subnet', () => {
    route.ifname = '';
    route.gateway = '10.100.0.1';
    failureObject.err =
      `Static route gateway ${route.gateway} not overlapped with any interface or tunnel`;
    const result = validateStaticRoute(device, tunnels, route);
    expect(result).toMatchObject(failureObject);
  });

  // conditional static routes
  it('Should be an invalid route if conditions is not an array', () => {
    route.conditions = 'test';
    failureObject.err = 'Static route conditions must be an array';
    const result = validateStaticRoute(device, tunnels, route);
    expect(result).toMatchObject(failureObject);
  });

  it('Should be a valid route if conditions is an empty array', () => {
    route.conditions = [];
    const result = validateStaticRoute(device, tunnels, route);
    expect(result).toMatchObject(successObject);
  });

  it('Should be an invalid route if conditions has multiple entries', () => {
    route.conditions = [{}, {}];
    failureObject.err = 'Multiple conditions for static route is not supported yet';
    const result = validateStaticRoute(device, tunnels, route);
    expect(result).toMatchObject(failureObject);
  });

  it('Should be an invalid route if condition has empty values', () => {
    route.conditions = [{
      destination: '',
      type: '',
      via: { devId: '', tunnelId: '' }
    }];
    const result = validateStaticRoute(device, tunnels, route);
    const staticRouteDescr = `${route.destination} via ${route.gateway}`;
    failureObject.err = `Condition for static route (${staticRouteDescr}) has empty values`;
    expect(result).toMatchObject(failureObject);
  });

  it('Should be an invalid route if only destination is empty', () => {
    route.conditions = [{
      destination: '',
      type: 'route-not-exists',
      via: { devId: 'pci', tunnelId: '3' }
    }];
    const staticRouteDescr = `${route.destination} via ${route.gateway}`;
    failureObject.err = `Partial condition for static route (${staticRouteDescr}) is not allowed`;
    const result = validateStaticRoute(device, tunnels, route);
    expect(result).toMatchObject(failureObject);
  });

  it('Should be an invalid route if only type is empty', () => {
    route.conditions = [{
      destination: '4.4.4.4/32',
      type: '',
      via: { devId: 'pci', tunnelId: '3' }
    }];
    const staticRouteDescr = `${route.destination} via ${route.gateway}`;
    failureObject.err = `Partial condition for static route (${staticRouteDescr}) is not allowed`;
    const result = validateStaticRoute(device, tunnels, route);
    expect(result).toMatchObject(failureObject);
  });

  it('Should be an invalid route if only via is empty', () => {
    route.conditions = [{
      destination: '4.4.4.4/32',
      type: 'route-exists',
      via: { }
    }];
    const staticRouteDescr = `${route.destination} via ${route.gateway}`;
    failureObject.err = `Partial condition for static route (${staticRouteDescr}) is not allowed`;
    const result = validateStaticRoute(device, tunnels, route);
    expect(result).toMatchObject(failureObject);
  });

  it('Should be an invalid route if devId and tunnelId provided in "via"', () => {
    route.conditions = [{
      destination: '4.4.4.4/32',
      type: 'route-exists',
      via: { devId: 'test', tunnelId: 'test' }
    }];
    const staticRouteDescr = `${route.destination} via ${route.gateway}`;
    failureObject.err = `Static route (${staticRouteDescr}) condition unsupported "via" value`;
    const result = validateStaticRoute(device, tunnels, route);
    expect(result).toMatchObject(failureObject);
  });

  it('Should be an invalid route if destination is not valid IP', () => {
    route.conditions = [{
      destination: 'test',
      type: 'route-exists',
      via: { devId: 'pci:0000:00:01.00' }
    }];
    const staticRouteDescr = `${route.destination} via ${route.gateway}`;
    failureObject.err = `Static route (${staticRouteDescr}) condition "destination" has invalid IP address`;
    const result = validateStaticRoute(device, tunnels, route);
    expect(result).toMatchObject(failureObject);
  });

  it('Should be a valid conditional route id devId found', () => {
    route.conditions = [{
      destination: '4.4.4.4/32',
      type: 'route-exists',
      via: { devId: 'pci:0000:00:01.00' }
    }];
    const result = validateStaticRoute(device, tunnels, route);
    expect(result).toMatchObject(successObject);
  });

  it('Should be a valid conditional route if tunnelId found', () => {
    route.conditions = [{
      destination: '4.4.4.4/32',
      type: 'route-exists',
      via: { tunnelId: 2 }
    }];
    const result = validateStaticRoute(device, tunnels, route);
    expect(result).toMatchObject(successObject);
  });

  it('Should be an invalid conditional route if devId is not found', () => {
    route.conditions = [{
      destination: '4.4.4.4/32',
      type: 'route-exists',
      via: { devId: 'pci:0000:00:07.00' }
    }];
    const staticRouteDescr = `${route.destination} via ${route.gateway}`;
    failureObject.err = `Static route (${staticRouteDescr}) condition interface pci:0000:00:07.00 is not found`;
    const result = validateStaticRoute(device, tunnels, route);
    expect(result).toMatchObject(failureObject);
  });

  it('Should be an invalid conditional route if tunnelId is not found', () => {
    route.conditions = [{
      destination: '4.4.4.4/32',
      type: 'route-exists',
      via: { tunnelId: 1 }
    }];
    const staticRouteDescr = `${route.destination} via ${route.gateway}`;
    failureObject.err = `Static route (${staticRouteDescr}) condition tunnel number 1 is not found`;
    const result = validateStaticRoute(device, tunnels, route);
    expect(result).toMatchObject(failureObject);
  });
});
