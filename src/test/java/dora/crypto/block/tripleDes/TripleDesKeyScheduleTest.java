package dora.crypto.block.tripleDes;

import dora.crypto.block.KeySchedule;
import net.jqwik.api.*;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

public class TripleDesKeyScheduleTest {

    @Property(tries = 100)
    void invalidKeySizeThrowsException(
            @ForAll byte[] key
    ) {
        Assume.that(key.length != 16 && key.length != 24);

        assertThatThrownBy(() -> {
            KeySchedule keySchedule = new TripleDesKeySchedule();
            keySchedule.roundKeys(key);
        })
                .isInstanceOf(IllegalArgumentException.class);
    }
}