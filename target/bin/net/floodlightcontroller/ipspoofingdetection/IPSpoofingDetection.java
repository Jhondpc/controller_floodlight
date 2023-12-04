package net.floodlightcontroller.ipspoofingdetection;

import java.util.Collection;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentSkipListSet;

import net.floodlightcontroller.core.IFloodlightProviderService;
import org.projectfloodlight.openflow.protocol.OFMessage;
import org.projectfloodlight.openflow.protocol.OFType;
import org.projectfloodlight.openflow.types.IPv4Address;
import org.projectfloodlight.openflow.types.MacAddress;

import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPv4;

public class IPSpoofingDetection implements IOFMessageListener, IFloodlightModule {

    protected IFloodlightProviderService floodlightProvider;
    protected Map<MacAddress, Set<IPv4Address>> macToIpMapping;

    @Override
    public String getName() {
        return IPSpoofingDetection.class.getSimpleName();
    }

    @Override
    public boolean isCallbackOrderingPrereq(OFType type, String name) {
        return false;
    }

    @Override
    public boolean isCallbackOrderingPostreq(OFType type, String name) {
        return false;
    }

    @Override
    public Collection<Class<? extends IFloodlightService>> getModuleServices() {
        return null;
    }

    @Override
    public Map<Class<? extends IFloodlightService>, IFloodlightService> getServiceImpls() {
        return null;
    }

    @Override
    public Collection<Class<? extends IFloodlightService>> getModuleDependencies() {
        Collection<Class<? extends IFloodlightService>> dependencies = new ConcurrentSkipListSet<>();
        dependencies.add(IFloodlightProviderService.class);
        return dependencies;
    }

    @Override
    public void init(FloodlightModuleContext context) throws FloodlightModuleException {
        floodlightProvider = context.getServiceImpl(IFloodlightProviderService.class);
        macToIpMapping = new ConcurrentHashMap<>();
    }

    @Override
    public void startUp(FloodlightModuleContext context) {
        floodlightProvider.addOFMessageListener(OFType.PACKET_IN, this);
    }

    @Override
    public Command receive(IOFSwitch sw, OFMessage msg, FloodlightContext cntx) {
        if (msg.getType() == OFType.PACKET_IN) {
            Ethernet eth = IFloodlightProviderService.bcStore.get(cntx, IFloodlightProviderService.CONTEXT_PI_PAYLOAD);

            MacAddress sourceMAC = eth.getSourceMACAddress();
            IPv4Address sourceIP = getSourceIPAddress(eth);

            macToIpMapping.computeIfAbsent(sourceMAC, k -> new ConcurrentSkipListSet<>()).add(sourceIP);

            if (macToIpMapping.get(sourceMAC).size() > 1) {
                System.out.println("Potential IP Spoofing detected. MAC: " + sourceMAC.toString() +
                        " IP: " + sourceIP.toString() + " Switch: " + sw.getId().toString());
            }
        }

        return Command.CONTINUE;
    }

    private IPv4Address getSourceIPAddress(Ethernet eth) {
        if (eth.getPayload() instanceof IPv4) {
            return ((IPv4) eth.getPayload()).getSourceAddress();
        }
        return IPv4Address.NONE;
    }
}
