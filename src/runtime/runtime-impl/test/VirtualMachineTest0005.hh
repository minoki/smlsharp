// VirtualMachineTest0005
// jp_ac_jaist_iml_runtime

#include "Heap.hh"
#include "Heap.hh"

#include "TestCase.h"
#include "TestSuite.h"

using std::string;

namespace jp_ac_jaist_iml_runtime
{

///////////////////////////////////////////////////////////////////////////////

/**
 *  Verifies that the pointers in the multiple stack frames of the VM are
 * traced at GC.
 *
 * <p><b>purpose of this test:</b></p>
 * <p>
 * </p>
 *
 * <p><b>supplementary comments:</b></p>
 *
 * <p><b>test cases:</b></p>
 *
 * <table border="1">
 * <caption>Test cases matrix</caption>
 * <tr>
 * <th>Case</th>
 * <th># of stack frames</th>
 * <th>comment</th>
 * </tr>
 *
 * <tr>
 * <th>0001</th>
 * <td>2</td>
 * <td>&nbsp;</td>
 * </tr>
 *
 * </table>
 *
 * <p><b>The detail of the test procedure:</b></p>
 *
 * <p>
 *  The sequence of these cases is as follows.
 * <ol>
 * <li>Sets up the VM and the heap.</li>
 * <li>Builds heap monitor and execution monitors and attaches them to the heap
 *    and the VM respectively. </li>
 * <li>Makes a code block which requires so much heap allocation that
 *    invokes garbage collection in the heap manager.</li>
 * <li>Calls the <code>execute</code> method on the VM with the code block
 *    as a parameter.</li>
 * <li>Checks the pointers in the pointer entries and record entries in the
 *    stack frames are updated to point at valid blocks.</li>
 * </ol>
 */
class VirtualMachineTest0005
    : public TestCase
{
    ////////////////////////////////////////
  private:

    ////////////////////////////////////////

  public:
    VirtualMachineTest0005(string name)
        : TestCase(name)
    {
    }

    virtual void setUp();

    virtual void tearDown();

    ////////////////////////////////////////
  public:

    /**
     *  Verifies that the pointers in the stack frames of the VM are traced
     * at GC.
     *
     * <p>prerequisite</p>
     * <ul>
     * <li>stack frames : 2
     *    <ul>
     *    <li>atoms : 1</li>
     *    <li>pointers : 1</li>
     *    <li>records : 1</li>
     *    </ul>
     * </ul>
     *
     * <p>expected result</p>
     * <ul>
     * <li>entries are updated</li>
     * <li>exceptions : not thrown</li>
     * </ul>
     */
    void testGC0001();

    class Suite;
};

class VirtualMachineTest0005::Suite
    : public TestSuite
{
    ////////////////////////////////////////
  public:
    Suite();
};

///////////////////////////////////////////////////////////////////////////////

}
