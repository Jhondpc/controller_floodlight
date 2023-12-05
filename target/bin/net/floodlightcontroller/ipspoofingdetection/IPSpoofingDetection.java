package net.floodlightcontroller.ipspoofingdetection;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentSkipListSet;

import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.util.FlowModUtils;
import org.projectfloodlight.openflow.protocol.*;
import org.projectfloodlight.openflow.protocol.action.OFAction;
import org.projectfloodlight.openflow.protocol.action.OFActions;
import org.projectfloodlight.openflow.protocol.instruction.OFInstruction;
import org.projectfloodlight.openflow.protocol.instruction.OFInstructions;
import org.projectfloodlight.openflow.protocol.match.Match;
import org.projectfloodlight.openflow.protocol.match.MatchField;
import org.projectfloodlight.openflow.types.*;

public class IPSpoofingDetection implements IOFMessageListener, IFloodlightModule {

    private static final int ICMP_PROTOCOL = IpProtocol.ICMP.getIpProtocolNumber();

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

                // Mitigar el ataque bloqueando el tráfico ICMP
                addFlowEntry(sw, sourceIP);
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

    private void addFlowEntry(IOFSwitch sw, IPv4Address sourceIP) {
        Match match = sw.getOFFactory().buildMatch()
                .setExact(MatchField.ETH_TYPE, EthType.IPv4)
                .setExact(MatchField.IPV4_SRC, sourceIP)
                .setExact(MatchField.IP_PROTO, IpProtocol.ICMP)
                .build();

        ArrayList<OFAction> actions = new ArrayList<>();
        OFActions actionsBuilder = sw.getOFFactory().actions();

        // Acción para descartar (DROP) el paquete ICMP
        OFAction drop = actionsBuilder.buildOutput().setPort(OFPort.CONTROLLER).build();
        actions.add(drop);

        ArrayList<OFInstruction> instructions = new ArrayList<>();
        OFInstructions instructionsBuilder = sw.getOFFactory().instructions();

        // Instrucción para aplicar las acciones (en este caso, descartar el paquete ICMP)
        OFInstruction applyActions = instructionsBuilder.buildApplyActions().setActions(actions).build();
        instructions.add(applyActions);

        sw.getOFFactory().buildFlowAdd()
                .setMatch(match)
                .setInstructions(instructions)
                .setPriority(FlowModUtils.PRIORITY_MAX)
                .setBufferId(OFBufferId.NO_BUFFER)
                .setHardTimeout(0)
                .setIdleTimeout(0)
                .setFlags(Collections.emptySet())
                .setCookie(U64.of(0))
                .build();
    }
}
